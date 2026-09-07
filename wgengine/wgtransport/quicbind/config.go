// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package quicbind carries IP packets over authenticated QUIC DATAGRAMs.
// The host Bind is an I/O interface, not a WireGuard encryption requirement.
// Legacy WG payloads are available only with ts_dev_wg_over_quic.
package quicbind

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/wgengine/wgtransport"
)

const ALPN = "quic-wg/1"   // Legacy ciphertext carrier, not HTTP/3.
const IPALPN = "quic-ip/1" // Native IP; never interchangeable with WG ciphertext.
const maxPeers = 256

// Config is immutable for the lifetime of a backend. Certificate pins are
// provisioned out-of-band, never learned from unauthenticated network packets.
// Native UDP preserves quic-go's batch/GSO fast path but needs explicit reachable
// endpoints. Magicsock reuses the existing NAT/DERP paths at additional I/O cost.
type Config struct {
	Version           int          `json:"version"`
	Payload           string       `json:"payload,omitempty"` // version 2 requires "ip"
	LocalPublicKey    string       `json:"local_public_key"`
	Certificate       string       `json:"certificate"`
	PrivateKey        string       `json:"private_key"`
	IO                string       `json:"io"`               // "magicsock" (default), or "udp"
	Listen            string       `json:"listen,omitempty"` // UDP mode only
	InitialPacketSize uint16       `json:"initial_packet_size,omitempty"`
	QueuePackets      int          `json:"queue_packets,omitempty"`
	Peers             []PeerConfig `json:"peers"`
	// HTTP3 selects a real CONNECT-IP request, not raw DATAGRAMs with h3 ALPN.
	HTTP3 bool `json:"http3,omitempty"`
	// AutoTrust binds each TLS session to the already-authorized Tailnet node
	// keys. It is H3/magicsock only and never learns trust from a certificate.
	AutoTrust bool `json:"auto_trust,omitempty"`
	// Server advertises this node as a browser-profile target. It does not
	// force a TLS role, open ports, grant access or disable mesh dialing.
	Server   bool   `json:"server,omitempty"`
	HTTP3URL string `json:"http3_url,omitempty"`
	// Optional HTTPS listener advertises the same HTTP/3 origin via Alt-Svc.
	HTTP3TCPListen string `json:"http3_tcp_listen,omitempty"`
}

type PeerConfig struct {
	PublicKey  string `json:"public_key"`
	SPKISHA256 string `json:"spki_sha256"`
	Endpoint   string `json:"endpoint,omitempty"`  // UDP mode only; literal IP:port
	HTTP3URL   string `json:"http3_url,omitempty"` // trusted https origin and CONNECT-IP path
	Server     bool   `json:"server,omitempty"`    // optional trusted public-card hint
}

type Factory struct {
	resetKey [32]byte // secret, derived from the persistent local TLS key
	last     atomic.Pointer[Backend]
	cfg      Config
	local    [32]byte
	cert     tls.Certificate
	peers    map[[32]byte]peerConfig
	byPin    map[[32]byte][32]byte
	http3URL *url.URL
}

type peerConfig struct {
	key      [32]byte
	pin      [32]byte
	address  *net.UDPAddr
	http3URL *url.URL
	server   bool
}

func (f *Factory) Mode() wgtransport.Mode {
	if f.cfg.HTTP3 {
		return wgtransport.HTTP3IP
	}
	if f.cfg.Payload == "ip" {
		return wgtransport.QUICIP
	}
	return wgtransport.QUIC
}
func (f *Factory) protocol() string {
	if f.cfg.HTTP3 {
		return "h3"
	}
	if f.cfg.Payload == "ip" {
		return IPALPN
	}
	return ALPN
}

func Load(path string) (*Factory, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read QUIC config: %w", err)
	}
	defer file.Close()
	var c Config
	dec := json.NewDecoder(io.LimitReader(file, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("invalid QUIC config: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("QUIC config must contain exactly one JSON object")
	}
	for _, p := range []*string{&c.Certificate, &c.PrivateKey} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	return NewFactory(c)
}

func parseKey(s string) (k [32]byte, err error) {
	s = strings.TrimPrefix(s, "nodekey:")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, errors.New("expected 64 hexadecimal characters")
	}
	copy(k[:], b)
	if k == ([32]byte{}) {
		return k, errors.New("zero key/pin is not allowed")
	}
	return k, nil
}

func NewFactory(c Config) (*Factory, error) {
	return newFactory(c, nil)
}

// NewFactoryWithCertificate lets mobile/embedded callers load identity from
// their own protected store. No file path or environment variable is required.
// The certificate must contain a software key supported by x509 PKCS#8.
func NewFactoryWithCertificate(c Config, identity tls.Certificate) (*Factory, error) {
	if c.Certificate != "" || c.PrivateKey != "" {
		return nil, errors.New("in-memory TLS identity cannot be combined with certificate file paths")
	}
	return newFactory(c, &identity)
}

func newFactory(c Config, identity *tls.Certificate) (*Factory, error) {
	switch c.Version {
	case 1:
		if !wgtransport.LegacyWGOverQUIC {
			return nil, fmt.Errorf("%w: version 1 WG-over-QUIC config is development-only; use native or version 2 payload=ip", wgtransport.ErrUnsupported)
		}
		if c.Payload != "" && c.Payload != "wireguard" {
			return nil, errors.New("version 1 only supports WireGuard payloads")
		}
		c.Payload = "wireguard"
	case 2:
		if c.Payload != "ip" {
			return nil, errors.New("version 2 requires explicit payload=ip")
		}
	default:
		return nil, errors.New("QUIC config must be version 2 with payload=ip")
	}
	if c.HTTP3 && c.Payload != "ip" {
		return nil, errors.New("HTTP/3 is supported only by native IP, never WG-over-QUIC")
	}
	var h3URL *url.URL
	if c.HTTP3 {
		var err error
		h3URL, err = parseHTTP3URL(c.HTTP3URL)
		if err != nil {
			return nil, err
		}
		// Keep QUIC's 1200-byte initial size on unknown/mobile paths. The
		// negotiated IP-fragment extension supplies the inner IPv6 MTU until
		// path MTU discovery permits whole IP datagrams; never require an
		// oversized Initial that can fail before the tunnel even negotiates.
		if c.HTTP3TCPListen != "" {
			host, port, err := net.SplitHostPort(c.HTTP3TCPListen)
			portNumber, portErr := strconv.Atoi(port)
			if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 || net.ParseIP(host) == nil {
				return nil, errors.New("invalid HTTP/3 TCP listen address")
			}
		}
	} else if c.HTTP3URL != "" || c.HTTP3TCPListen != "" || c.Server {
		return nil, errors.New("HTTP/3 options require http3=true")
	}
	if c.IO == "" {
		c.IO = "magicsock"
	}
	if c.IO != "magicsock" && c.IO != "udp" {
		return nil, errors.New("QUIC io must be magicsock or udp")
	}
	if c.AutoTrust && (!c.HTTP3 || c.Payload != "ip" || c.IO != "magicsock") {
		return nil, errors.New("automatic node trust requires HTTP/3 native IP over magicsock")
	}
	if c.IO == "udp" && !supportsIndependentUDP(runtime.GOOS) {
		return nil, fmt.Errorf("%s requires io=magicsock so QUIC participates in the host VPN socket-protection and rebind lifecycle", runtime.GOOS)
	}
	if c.HTTP3TCPListen != "" && !supportsIndependentUDP(runtime.GOOS) {
		return nil, fmt.Errorf("public HTTPS listening is not supported inside the %s VPN client", runtime.GOOS)
	}
	if c.QueuePackets == 0 {
		c.QueuePackets = 256
	}
	if c.QueuePackets < 32 || c.QueuePackets > 2048 {
		return nil, errors.New("queue_packets must be 32..2048")
	}
	if c.InitialPacketSize == 0 {
		c.InitialPacketSize = 1200
	}
	if c.InitialPacketSize < 1200 || c.InitialPacketSize > 1400 {
		return nil, errors.New("initial_packet_size must be 1200..1400")
	}
	if (!c.AutoTrust && len(c.Peers) == 0) || len(c.Peers) > maxPeers {
		return nil, fmt.Errorf("QUIC requires 1..%d explicitly pinned peers", maxPeers)
	}
	local, err := parseKey(c.LocalPublicKey)
	if err != nil {
		return nil, fmt.Errorf("local_public_key: %w", err)
	}
	var cert tls.Certificate
	if identity == nil {
		cert, err = tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("QUIC TLS identity: %w", err)
		}
	} else {
		cert = *identity
		cert.Certificate = make([][]byte, len(identity.Certificate))
		for i, der := range identity.Certificate {
			cert.Certificate[i] = bytes.Clone(der)
		}
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("empty QUIC TLS identity")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := validCertificate(leaf); err != nil {
		return nil, err
	}
	// tls.LoadX509KeyPair verifies file-backed pairs. Embedded callers can
	// construct tls.Certificate directly, so validate the same invariant here
	// before advertising an unusable identity or starting network workers.
	if err := validateLocalCertificateKey(cert, leaf); err != nil {
		return nil, err
	}
	cert.Leaf = leaf
	f := &Factory{cfg: c, local: local, cert: cert, peers: make(map[[32]byte]peerConfig), byPin: make(map[[32]byte][32]byte), http3URL: h3URL}
	privateDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derive QUIC reset key: %w", err)
	}
	derive := hmac.New(sha256.New, privateDER)
	derive.Write([]byte(f.protocol() + "/stateless-reset"))
	copy(f.resetKey[:], derive.Sum(nil))
	clear(privateDER)
	ownPin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	for _, p := range c.Peers {
		key, err := parseKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("peer public key: %w", err)
		}
		pin, err := parseKey(p.SPKISHA256)
		if err != nil {
			return nil, fmt.Errorf("peer TLS pin: %w", err)
		}
		if key == local || pin == ownPin {
			return nil, errors.New("peer cannot reuse the local WG or TLS identity")
		}
		if _, ok := f.peers[key]; ok {
			return nil, errors.New("duplicate QUIC peer")
		}
		if _, ok := f.byPin[pin]; ok {
			return nil, errors.New("TLS pin must map to exactly one WG peer")
		}
		pc := peerConfig{key: key, pin: pin, server: p.Server}
		if c.HTTP3 {
			pc.http3URL, err = parseHTTP3URL(p.HTTP3URL)
			if err != nil {
				return nil, fmt.Errorf("peer HTTP/3 URL: %w", err)
			}
		} else if p.HTTP3URL != "" {
			return nil, errors.New("peer http3_url requires http3=true")
		}
		if c.IO == "udp" {
			ap, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil || ap == nil || ap.IP == nil || ap.Port <= 0 {
				return nil, errors.New("UDP peers require a valid endpoint")
			}
			host, _, err := net.SplitHostPort(p.Endpoint)
			if err != nil || net.ParseIP(host) == nil {
				return nil, errors.New("UDP endpoint must use a literal IP, not DNS")
			}
			if ap.IP.IsUnspecified() || ap.IP.IsMulticast() {
				return nil, errors.New("invalid UDP peer address")
			}
			pc.address = ap
		} else if p.Endpoint != "" {
			return nil, errors.New("magicsock mode resolves peers through the host, not endpoint overrides")
		}
		f.peers[key] = pc
		f.byPin[pin] = key
	}
	if c.IO == "udp" {
		a, err := net.ResolveUDPAddr("udp", c.Listen)
		if err != nil || a == nil || a.Port < 0 {
			return nil, errors.New("invalid UDP listen address")
		}
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || net.ParseIP(host) == nil {
			return nil, errors.New("UDP listen must contain a literal IP")
		}
	} else if c.Listen != "" {
		return nil, errors.New("listen is only used by UDP mode")
	}
	return f, nil
}

func validateLocalCertificateKey(cert tls.Certificate, leaf *x509.Certificate) error {
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok || signer == nil || (reflect.ValueOf(signer).Kind() == reflect.Pointer && reflect.ValueOf(signer).IsNil()) {
		return errors.New("QUIC TLS identity requires a signing private key")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, leaf.RawSubjectPublicKeyInfo) {
		return errors.New("QUIC TLS certificate and private key do not match")
	}
	return nil
}

func validCertificate(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("QUIC certificate is not currently valid")
	}
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return errors.New("missing certificate public key")
	}
	return nil
}

func (f *Factory) verify(cs tls.ConnectionState, expected *[32]byte) ([32]byte, error) {
	var none [32]byte
	if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != f.protocol() {
		return none, errors.New("QUIC TLS version/ALPN mismatch")
	}
	if len(cs.PeerCertificates) == 0 {
		return none, errors.New("QUIC requires a peer certificate")
	}
	cert := cs.PeerCertificates[0]
	if err := validCertificate(cert); err != nil {
		return none, err
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	key, ok := f.byPin[pin]
	if !ok {
		return none, errors.New("untrusted QUIC certificate pin")
	}
	if expected != nil && !bytes.Equal(key[:], expected[:]) {
		return none, errors.New("QUIC certificate belongs to a different WireGuard peer")
	}
	return key, nil
}

func (f *Factory) tlsConfig(expected *[32]byte) *tls.Config {
	clientAuth := tls.RequireAnyClientCert
	if f.cfg.HTTP3 && expected == nil {
		clientAuth = tls.NoClientCert
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{f.protocol()}, Certificates: []tls.Certificate{f.cert},
		// The client pins the TLS server. Raw QUIC additionally pins the TLS
		// client; HTTP/3 authenticates the peer inside the CONNECT request
		// instead, keeping ordinary public-site TLS free of CertificateRequest.
		InsecureSkipVerify: true, ClientAuth: clientAuth,
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Browsers may fetch the public site without a client certificate.
			// The CONNECT handler always requires a pinned, live peer identity.
			if f.cfg.HTTP3 && expected == nil && len(cs.PeerCertificates) == 0 {
				return nil
			}
			_, err := f.verify(cs, expected)
			return err
		},
	}
}
