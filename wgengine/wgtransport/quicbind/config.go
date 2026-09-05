// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package quicbind carries complete WG/AWG messages over authenticated QUIC
// DATAGRAMs. It preserves the host Bind API, not WireGuard's outer wire format.
// Both ends must explicitly opt in. There is never a native-WG fallback.
package quicbind

import (
	"bytes"
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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"tailscale.com/wgengine/wgtransport"
)

const ALPN = "quic-wg/1" // Real QUIC application, deliberately NOT claiming HTTP/3.
const maxPeers = 256

// Config is immutable for the lifetime of a backend. Certificate pins are
// provisioned out-of-band, never learned from unauthenticated network packets.
// Native UDP preserves quic-go's batch/GSO fast path but needs explicit reachable
// endpoints. Magicsock reuses the existing NAT/DERP paths at additional I/O cost.
type Config struct {
	Version           int          `json:"version"`
	LocalPublicKey    string       `json:"local_public_key"`
	Certificate       string       `json:"certificate"`
	PrivateKey        string       `json:"private_key"`
	IO                string       `json:"io"`               // "magicsock" (default), or "udp"
	Listen            string       `json:"listen,omitempty"` // UDP mode only
	InitialPacketSize uint16       `json:"initial_packet_size,omitempty"`
	QueuePackets      int          `json:"queue_packets,omitempty"`
	Peers             []PeerConfig `json:"peers"`
}

type PeerConfig struct {
	PublicKey  string `json:"public_key"`
	SPKISHA256 string `json:"spki_sha256"`
	Endpoint   string `json:"endpoint,omitempty"` // UDP mode only; literal IP:port
}

type Factory struct {
	resetKey [32]byte // secret, derived from the persistent local TLS key
	last     atomic.Pointer[Backend]
	cfg      Config
	local    [32]byte
	cert     tls.Certificate
	peers    map[[32]byte]peerConfig
	byPin    map[[32]byte][32]byte
}

type peerConfig struct {
	key     [32]byte
	pin     [32]byte
	address *net.UDPAddr
}

func (f *Factory) Mode() wgtransport.Mode { return wgtransport.QUIC }

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
	if c.Version != 1 {
		return nil, errors.New("QUIC config version must be 1")
	}
	if c.IO == "" {
		c.IO = "magicsock"
	}
	if c.IO != "magicsock" && c.IO != "udp" {
		return nil, errors.New("QUIC io must be magicsock or udp")
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
	if len(c.Peers) == 0 || len(c.Peers) > maxPeers {
		return nil, fmt.Errorf("QUIC requires 1..%d explicitly pinned peers", maxPeers)
	}
	local, err := parseKey(c.LocalPublicKey)
	if err != nil {
		return nil, fmt.Errorf("local_public_key: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("QUIC TLS identity: %w", err)
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
	cert.Leaf = leaf
	f := &Factory{cfg: c, local: local, cert: cert, peers: make(map[[32]byte]peerConfig), byPin: make(map[[32]byte][32]byte)}
	privateDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("derive QUIC reset key: %w", err)
	}
	derive := hmac.New(sha256.New, privateDER)
	derive.Write([]byte("quic-wg/1/stateless-reset"))
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
		pc := peerConfig{key: key, pin: pin}
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

func validCertificate(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return errors.New("QUIC certificate is not currently valid")
	}
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return errors.New("missing certificate public key")
	}
	return nil
}

func (f *Factory) verify(cs tls.ConnectionState, expected *[32]byte) ([32]byte, error) {
	var none [32]byte
	if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != ALPN {
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
	return &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, Certificates: []tls.Certificate{f.cert},
		// PKI hostname validation is replaced by the mandatory pinned-SPKI verifier
		// on BOTH client and server. TLS still verifies CertificateVerify possession.
		// There is intentionally no configuration option to bypass this verifier.
		InsecureSkipVerify: true, ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error { _, err := f.verify(cs, expected); return err },
	}
}
