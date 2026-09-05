// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/LiuTangLei/wireguard-go/device"
	"github.com/LiuTangLei/wireguard-go/tun/tuntest"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgtransport"
)

func testIdentity(t testing.TB) (certPath, keyPath, pin string) {
	t.Helper()
	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "quic-wg test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, DNSNames: []string{"quic-wg"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return certPath, keyPath, hex.EncodeToString(h[:])
}
func freeUDP(t testing.TB) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	a := c.LocalAddr().String()
	c.Close()
	return a
}

type keyedBind struct {
	conn.Bind
	mu     sync.Mutex
	key    string
	remote string
	avoid  [2]uint16 // prevent the host bind taking a reserved test QUIC port
}

func (b *keyedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	for range 16 {
		fns, actual, err := b.Bind.Open(port)
		if err != nil {
			return nil, 0, err
		}
		if actual != b.avoid[0] && actual != b.avoid[1] {
			return fns, actual, nil
		}
		_ = b.Bind.Close()
		if port != 0 {
			break
		}
	}
	return nil, 0, errors.New("test host bind could not avoid reserved QUIC ports")
}

func (b *keyedBind) ParseEndpoint(k string) (conn.Endpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if k != b.key || b.remote == "" {
		return nil, ErrUnknownPeer
	}
	return b.Bind.ParseEndpoint(b.remote)
}
func (b *keyedBind) setRemote(a string) { b.mu.Lock(); b.remote = a; b.mu.Unlock() }

type testPair struct {
	backends [2]*Backend
	bases    [2]*keyedBind
	keys     [2]key.NodePrivate
}

func newTestPair(t testing.TB, mode string, options ...func(*Config)) *testPair {
	t.Helper()
	h3 := strings.HasPrefix(mode, "http3-")
	mode = strings.TrimPrefix(mode, "http3-")
	if mode == "udp" && !supportsIndependentUDP(runtime.GOOS) {
		t.Skip("mobile/browser clients use the protected magicsock path")
	}
	p := new(testPair)
	var configs [2]Config
	var pins [2]string
	var addresses [2]string
	for i := range 2 {
		p.keys[i] = key.NewNode()
		pk := p.keys[i].Public().Raw32()
		cert, k, pin := testIdentity(t)
		pins[i] = pin
		addresses[i] = freeUDP(t)
		for i > 0 && addresses[i] == addresses[0] {
			addresses[i] = freeUDP(t)
		}
		configs[i] = Config{Version: 2, Payload: "ip", LocalPublicKey: hex.EncodeToString(pk[:]), Certificate: cert, PrivateKey: k, IO: mode, InitialPacketSize: 1200, QueuePackets: 256}
		if mode == "udp" {
			configs[i].Listen = addresses[i]
		}
	}
	for i := range 2 {
		peerKey := p.keys[i^1].Public().Raw32()
		peerKeyString := hex.EncodeToString(peerKey[:])
		pc := PeerConfig{PublicKey: peerKeyString, SPKISHA256: pins[i^1]}
		if mode == "udp" {
			pc.Endpoint = addresses[i^1]
		}
		configs[i].Peers = []PeerConfig{pc}
		if h3 {
			configs[i].HTTP3 = true
			configs[i].InitialPacketSize = 1400
			configs[i].HTTP3URL = "https://quic-ip.test/.well-known/masque/ip/*/*/"
			configs[i].Peers[0].HTTP3URL = configs[i].HTTP3URL
		}
		for _, option := range options {
			option(&configs[i])
		}
		f, err := NewFactory(configs[i])
		if err != nil {
			t.Fatal(err)
		}
		p.bases[i] = &keyedBind{Bind: conn.NewDefaultBind(), key: peerKeyString, remote: "127.0.0.1:9"}
		for j, address := range addresses {
			a, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			p.bases[i].avoid[j] = uint16(a.Port)
		}
		listener := new(net.ListenConfig)
		backend, err := f.New(wgtransport.Host{Bind: p.bases[i], Logf: t.Logf, ListenPacket: listener.ListenPacket, PeerAllowed: func([32]byte) bool { return true }})
		if err != nil {
			t.Fatal(err)
		}
		p.backends[i] = backend.(*Backend)
		p.backends[i].LocalIdentityChanged(p.keys[i].Public().Raw32())
		b := p.backends[i]
		t.Cleanup(func() { b.Close() })
	}
	return p
}
func (p *testPair) open(t testing.TB) (fns [2]conn.ReceiveFunc) {
	t.Helper()
	for i, b := range p.backends {
		fs, port, err := b.Bind().Open(0)
		if err != nil {
			t.Fatal(err)
		}
		fns[i] = fs[0]
		p.bases[i^1].setRemote(fmt.Sprintf("127.0.0.1:%d", port))
	}
	return
}
func readOne(t testing.TB, fn conn.ReceiveFunc) []byte {
	t.Helper()
	result := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, maxPacket)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := fn([][]byte{buf}, sizes, eps)
		if err != nil {
			errCh <- err
			return
		}
		if n != 1 || sizes[0] == 0 {
			errCh <- errors.New("empty receive")
			return
		}
		result <- buf[:sizes[0]]
	}()
	select {
	case p := <-result:
		return p
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(12 * time.Second):
		t.Fatal("QUIC receive timed out")
	}
	return nil
}

func TestQUICBidirectionalAndReopen(t *testing.T) {
	for _, mode := range []string{"udp", "magicsock", "http3-udp", "http3-magicsock"} {
		t.Run(mode, func(t *testing.T) {
			p := newTestPair(t, mode)
			for cycle := range 2 {
				fns := p.open(t)
				for i := range 2 {
					pk := p.keys[i^1].Public().Raw32()
					ep, err := p.backends[i].Bind().ParseEndpoint(hex.EncodeToString(pk[:]))
					if err != nil {
						t.Fatal(err)
					}
					for _, size := range []int{32, 1280, 2048, 16000} {
						payload := bytes.Repeat([]byte{byte(i + cycle + 17)}, size)
						wire := append(make([]byte, 8), payload...)
						if err := p.backends[i].Bind().Send([][]byte{wire}, ep, 8); err != nil {
							t.Fatal(err)
						}
						if got := readOne(t, fns[i^1]); !bytes.Equal(got, payload) {
							t.Fatalf("size %d mismatch", size)
						}
					}
				}
				for _, b := range p.backends {
					if err := b.Bind().Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestRealWGAndAWGOverQUIC(t *testing.T) {
	if !wgtransport.LegacyWGOverQUIC {
		t.Skip("development-only WG-over-QUIC")
	}
	for _, mode := range []string{"udp", "magicsock"} {
		for _, awg := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/awg=%v", mode, awg), func(t *testing.T) {
				p := newTestPair(t, mode, func(c *Config) { c.Version = 1; c.Payload = "wireguard" })
				var devs [2]*device.Device
				var tuns [2]*tuntest.ChannelTUN
				for i := range 2 {
					tuns[i] = tuntest.NewChannelTUN()
					devs[i] = device.NewDevice(tuns[i].TUN(), p.backends[i].Bind(), device.NewLogger(device.LogLevelError, "quic-test "))
					d := devs[i]
					t.Cleanup(d.Close)
					profile := ""
					if awg {
						profile = "s1=20\ns2=24\ns3=16\ns4=16\nheader_protection_key=" + strings.Repeat("12", 32) + "\nrandom_trailers=true\ndisable_cookies=true\n"
					}
					priv := key.NodePrivateAs[device.NoisePrivateKey](p.keys[i])
					pub := p.keys[i^1].Public().Raw32()
					if err := d.IpcSet(profile + fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=10.89.0.%d/32\n", priv, pub, (i^1)+1)); err != nil {
						t.Fatal(err)
					}
					if err := d.Up(); err != nil {
						t.Fatal(err)
					}
					p.bases[i^1].setRemote(fmt.Sprintf("127.0.0.1:%d", p.backends[i].active.Load().port))
				}
				for i, d := range devs {
					pub := p.keys[i^1].Public().Raw32()
					if err := d.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=%x\n", pub, pub)); err != nil {
						t.Fatal(err)
					}
				}
				for i := range 2 {
					src := netip.AddrFrom4([4]byte{10, 89, 0, byte(i + 1)})
					dst := netip.AddrFrom4([4]byte{10, 89, 0, byte((i ^ 1) + 1)})
					packet := tuntest.Ping(dst, src)
					select {
					case tuns[i].Outbound <- packet:
					case <-time.After(5 * time.Second):
						t.Fatal("TUN send blocked")
					}
					select {
					case got := <-tuns[i^1].Inbound:
						if !bytes.Equal(got, packet) {
							t.Fatal("WG plaintext differs")
						}
					case <-time.After(12 * time.Second):
						t.Fatal("WG/QUIC encrypted transit failed")
					}
				}
				for _, b := range p.backends {
					if b.counters.Connections.Load() == 0 || b.counters.ReceivedPackets.Load() == 0 {
						t.Fatal("QUIC was bypassed")
					}
				}
			})
		}
	}
}

func TestQUICRejectsWrongIdentityAndUnknownPeer(t *testing.T) {
	p := newTestPair(t, "udp")
	p.open(t)
	b := p.backends[0]
	pk := p.keys[1].Public().Raw32()
	ep, err := b.Bind().ParseEndpoint(hex.EncodeToString(pk[:]))
	if err != nil {
		t.Fatal(err)
	}
	b.LocalIdentityChanged([32]byte{99})
	if err := b.Bind().Send([][]byte{{1, 2, 3}}, ep, 0); !errors.Is(err, ErrIdentity) {
		t.Fatalf("identity error: %v", err)
	}
	if _, err := b.Bind().ParseEndpoint(strings.Repeat("ff", 32)); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("unknown peer: %v", err)
	}
}

func TestQUICPinVerification(t *testing.T) {
	p := newTestPair(t, "udp")
	a, b := p.backends[0].factory, p.backends[1].factory
	state := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: a.protocol(), PeerCertificates: []*x509.Certificate{b.cert.Leaf}}
	if _, err := a.verify(state, &b.local); err != nil {
		t.Fatal(err)
	}
	if _, err := a.verify(state, &a.local); err == nil {
		t.Fatal("wrong WG peer accepted")
	}
	state.PeerCertificates = []*x509.Certificate{a.cert.Leaf}
	if _, err := a.verify(state, nil); err == nil {
		t.Fatal("untrusted pin accepted")
	}
}
