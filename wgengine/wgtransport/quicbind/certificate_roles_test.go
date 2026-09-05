// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"testing"
)

// Model the serverAuth-only EKU of contemporary public web certificates. The
// fixture is locally signed, NOT a claim that a public CA issued this identity.
// HTTP/3 authenticates the node inside CONNECT, not with TLS clientAuth.
func TestHTTP3WorksWithoutClientAuthEKU(t *testing.T) {
	pair := newTestPair(t, "http3-udp", func(c *Config) {
		identity, err := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(identity.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, identity.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	})
	fns := pair.open(t)
	for i, b := range pair.backends {
		if got := b.factory.cert.Leaf.ExtKeyUsage; len(got) != 1 || got[0] != x509.ExtKeyUsageServerAuth {
			t.Fatal("fixture still has clientAuth", got)
		}
		peerKey := pair.keys[i^1].Public().Raw32()
		ep, err := b.Bind().ParseEndpoint(hex.EncodeToString(peerKey[:]))
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Repeat([]byte{0x45, byte(i + 1)}, 512)
		if err := b.Bind().Send([][]byte{want}, ep, 0); err != nil {
			t.Fatal(err)
		}
		if got := readOne(t, fns[i^1]); !bytes.Equal(got, want) {
			t.Fatal("HTTP/3 payload differs")
		}
		if b.factory.protocol() != "h3" {
			t.Fatal("not HTTP/3")
		}
	}
}

func TestInMemoryCertificateKeyMustMatch(t *testing.T) {
	pair := newTestPair(t, "udp")
	f := pair.backends[0].factory
	cfg := f.cfg
	cfg.Certificate, cfg.PrivateKey = "", ""
	for _, wrong := range []any{nil, (*ecdsa.PrivateKey)(nil), pair.backends[1].factory.cert.PrivateKey} {
		identity := f.cert
		identity.PrivateKey = wrong
		if _, err := NewFactoryWithCertificate(cfg, identity); err == nil {
			t.Fatal("accepted invalid in-memory certificate/key pair")
		}
	}
	if _, err := NewFactoryWithCertificate(cfg, f.cert); err != nil {
		t.Fatal("rejected valid in-memory identity", err)
	}
}
