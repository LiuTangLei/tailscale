// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgtransport

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/LiuTangLei/wireguard-go/device"
	"github.com/LiuTangLei/wireguard-go/tun/tuntest"
	"tailscale.com/types/key"
)

type testFactory struct {
	mode    Mode
	backend Backend
	err     error
}

func (f *testFactory) Mode() Mode                  { return f.mode }
func (f *testFactory) New(h Host) (Backend, error) { return f.backend, f.err }

type testBackend struct {
	bind                 conn.Bind
	closes               int
	identities, removals [][32]byte
	networks             [][2]bool
}

func (b *testBackend) Bind() conn.Bind                 { return b.bind }
func (b *testBackend) Close() error                    { b.closes++; return nil }
func (b *testBackend) LocalIdentityChanged(k [32]byte) { b.identities = append(b.identities, k) }
func (b *testBackend) PeerRemoved(k [32]byte)          { b.removals = append(b.removals, k) }
func (b *testBackend) NetworkChanged(up, rebind bool) {
	b.networks = append(b.networks, [2]bool{up, rebind})
}

func TestNativePreservesBind(t *testing.T) {
	base := conn.NewDefaultBind()
	m, err := New(Host{Bind: base}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if m.Bind() != base || m.Mode() != Native {
		t.Fatal("native did not preserve bind identity")
	}
	for range 2 {
		if _, _, err := m.Bind().Open(0); err != nil {
			t.Fatal(err)
		}
		if err := m.Bind().Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	// Final manager close does not take ownership of the native socket.
	if _, _, err := base.Open(0); err != nil {
		t.Fatal(err)
	}
	base.Close()
}

func TestResolveFailClosed(t *testing.T) {
	for _, mode := range []string{"quic", "quci", "awg", "wg", "QUIC"} {
		if _, err := Resolve(Config{}, mode); err == nil {
			t.Errorf("accepted unavailable mode %q", mode)
		}
	}
	var typedNil *testFactory
	if _, err := Resolve(Config{Mode: QUIC, Factory: typedNil}, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("typed nil: %v", err)
	}
	if _, err := Resolve(Config{Mode: QUIC, Factory: &testFactory{mode: Native}}, ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("mismatch: %v", err)
	}
	c, err := Resolve(Config{Mode: Native}, "quic")
	if err != nil || c.Mode != Native {
		t.Fatalf("explicit config precedence: %+v %v", c, err)
	}
	if _, err := New(Host{}, Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil bind: %v", err)
	}
}

func TestFactoryCleanupAndLifecycle(t *testing.T) {
	base := conn.NewDefaultBind()
	for _, tc := range []struct {
		name string
		b    *testBackend
		err  error
	}{
		{"constructor", &testBackend{bind: base}, errors.New("constructor failed")},
		{"nil-bind", &testBackend{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Host{Bind: base}, Config{Mode: QUIC, Factory: &testFactory{mode: QUIC, backend: tc.b, err: tc.err}})
			if err == nil || tc.b.closes != 1 {
				t.Fatalf("err=%v closes=%d", err, tc.b.closes)
			}
		})
	}
	b := &testBackend{bind: base}
	m, err := New(Host{Bind: base}, Config{Mode: QUIC, Factory: &testFactory{mode: QUIC, backend: b}})
	if err != nil {
		t.Fatal(err)
	}
	k := [32]byte{1}
	m.LocalIdentityChanged(k)
	m.LocalIdentityChanged(k)
	m.PeerRemoved(k)
	m.NetworkChanged(true, true)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m.Close()
	m.LocalIdentityChanged([32]byte{2})
	m.PeerRemoved(k)
	m.NetworkChanged(false, false)
	if b.closes != 1 || len(b.identities) != 1 || len(b.removals) != 1 || len(b.networks) != 1 {
		t.Fatalf("lifecycle %+v", b)
	}
}

type awareEndpoint struct {
	conn.Endpoint
	initiation, peer [32]byte
}

func (e *awareEndpoint) InitiationMessagePublicKey(k [32]byte) { e.initiation = k }
func (e *awareEndpoint) FromPeer(k [32]byte)                   { e.peer = k }

type cyclicEndpoint struct{ conn.Endpoint }

func (e *cyclicEndpoint) UnderlyingEndpoint() conn.Endpoint { return e }

func TestEndpointIdentityAndUnwrap(t *testing.T) {
	base := conn.NewDefaultBind()
	ep, err := base.ParseEndpoint("127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	a := &awareEndpoint{Endpoint: ep}
	w, err := WrapEndpoint(a)
	if err != nil {
		t.Fatal(err)
	}
	outer, _ := WrapEndpoint(w)
	k := [32]byte{9}
	outer.InitiationMessagePublicKey(k)
	outer.FromPeer(k)
	if a.initiation != k || a.peer != k {
		t.Fatal("identity callback lost")
	}
	raw, err := UnwrapEndpoint(outer)
	if err != nil || raw != a {
		t.Fatalf("unwrap %v %v", raw, err)
	}
	if !bytes.Equal(outer.DstToBytes(), a.DstToBytes()) {
		t.Fatal("cookie identity changed")
	}
	if _, err := UnwrapEndpoint(&cyclicEndpoint{Endpoint: ep}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("cycle: %v", err)
	}
	var nilWrapper *Endpoint
	if _, err := UnwrapEndpoint(nilWrapper); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("typed nil: %v", err)
	}
}

// countingBind is a TEST carrier, not QUIC. It wraps/unwraps endpoints and
// delegates the complete batch/offset contract to a real localhost UDP Bind.
type countingBind struct {
	conn.Bind
	sends    atomic.Int64
	receives atomic.Int64
}

func (b *countingBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	raw, err := UnwrapEndpoint(ep)
	if err != nil {
		return err
	}
	b.sends.Add(int64(len(bufs)))
	return b.Bind.Send(bufs, raw, offset)
}
func (b *countingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ep, err := b.Bind.ParseEndpoint(s)
	if err != nil {
		return nil, err
	}
	return WrapEndpoint(ep)
}
func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, p, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(bufs, sizes, eps)
			for j := 0; j < n; j++ {
				if sizes[j] > 0 {
					eps[j], _ = WrapEndpoint(eps[j])
					b.receives.Add(1)
				}
			}
			return n, err
		}
	}
	return fns, p, nil
}

func TestRealWireGuardThroughCarrier(t *testing.T) {
	profiles := map[string]string{
		"wg":    "",
		"awg2":  "s1=20\ns2=24\ns3=16\nh1=100001\nh2=200002\nh3=300003\nh4=400004\n",
		"awg3":  "s1=20\ns2=24\ns3=16\ns4=16\nh1=100001-100099\nh2=200001-200099\nh3=300001-300099\nh4=400001-400099\nheader_protection_key=" + strings.Repeat("12", 32) + "\ncontent_padding_addition=0-16\n",
		"awg31": "s1=20\ns2=24\ns3=16\ns4=16\nrandom_trailers=true\ndisable_cookies=true\n",
	}
	for name, profile := range profiles {
		t.Run(name, func(t *testing.T) {
			var devs [2]*device.Device
			var tuns [2]*tuntest.ChannelTUN
			var managers [2]*Manager
			var carriers [2]*countingBind
			keys := [2]key.NodePrivate{key.NewNode(), key.NewNode()}
			ports := [2]int{}
			for i := range 2 {
				base := conn.NewDefaultBind()
				carriers[i] = &countingBind{Bind: base}
				backend := &testBackend{bind: carriers[i]}
				var err error
				managers[i], err = New(Host{Bind: base}, Config{Mode: QUIC, Factory: &testFactory{mode: QUIC, backend: backend}})
				if err != nil {
					t.Fatal(err)
				}
				tuns[i] = tuntest.NewChannelTUN()
				devs[i] = device.NewDevice(tuns[i].TUN(), managers[i].Bind(), device.NewLogger(device.LogLevelError, ""))
				dev := devs[i]
				manager := managers[i]
				t.Cleanup(func() { dev.Close(); manager.Close() })
				private := key.NodePrivateAs[device.NoisePrivateKey](keys[i])
				public := keys[i^1].Public().Raw32()
				config := fmt.Sprintf("private_key=%x\nlisten_port=0\npublic_key=%x\nallowed_ip=10.88.0.%d/32\n", private, public, (i^1)+1)
				// Device-wide options must precede the first peer in a UAPI update.
				if err := dev.IpcSet(profile + config); err != nil {
					t.Fatal(err)
				}
				if err := dev.Up(); err != nil {
					t.Fatal(err)
				}
				state, err := dev.IpcGet()
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(state, "\n") {
					if strings.HasPrefix(line, "listen_port=") {
						fmt.Sscanf(line, "listen_port=%d", &ports[i])
					}
				}
				if ports[i] == 0 {
					t.Fatal("missing bound port")
				}
			}
			for i, dev := range devs {
				public := keys[i^1].Public().Raw32()
				if err := dev.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=127.0.0.1:%d\n", public, ports[i^1])); err != nil {
					t.Fatal(err)
				}
			}
			for i := range 2 {
				src := netip.AddrFrom4([4]byte{10, 88, 0, byte(i + 1)})
				dst := netip.AddrFrom4([4]byte{10, 88, 0, byte((i ^ 1) + 1)})
				pkt := tuntest.Ping(dst, src)
				select {
				case tuns[i].Outbound <- pkt:
				case <-time.After(5 * time.Second):
					t.Fatal("TUN send timeout")
				}
				select {
				case got := <-tuns[i^1].Inbound:
					if !bytes.Equal(pkt, got) {
						t.Fatal("decrypted payload differs")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("encrypted packet did not transit carrier")
				}
			}
			for _, b := range carriers {
				if b.sends.Load() == 0 || b.receives.Load() == 0 {
					t.Fatal("carrier was bypassed")
				}
			}
		})
	}
}
