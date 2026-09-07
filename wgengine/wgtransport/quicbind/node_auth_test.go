// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"tailscale.com/wgengine/wgtransport"
)

func TestAutoTrustNoCardsAndRebind(t *testing.T) {
	for _, servers := range [][2]bool{{false, false}, {false, true}, {true, true}, {true, false}} {
		t.Run(serverHintValue(servers[0])+serverHintValue(servers[1]), func(t *testing.T) {
			index := 0
			pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil; c.Server = servers[index]; index++ })
			fns := pair.open(t)
			for cycle := range 3 {
				if cycle > 0 {
					for _, b := range pair.backends {
						b.NetworkChanged(true, true)
					}
				}
				p, err := pair.backends[0].active.Load().peer(pair.keys[1].Public().Raw32(), nil)
				if err != nil {
					t.Fatal(err)
				}
				s, err := p.getSession()
				if err != nil {
					t.Fatal(err)
				}
				wantProfile := ""
				if cycle > 0 && !servers[0] && servers[1] {
					wantProfile = "chromium-h3"
				}
				if s.q.ConnectionState().ClientHelloProfile != wantProfile {
					t.Fatal("wrong actual profile", cycle, s.q.ConnectionState().ClientHelloProfile)
				}
				for i := range 2 {
					remote := pair.keys[i^1].Public().Raw32()
					ep, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
					if err != nil {
						t.Fatal(err)
					}
					want := bytes.Repeat([]byte{0x45, byte(i), byte(cycle)}, 256)
					if err := pair.backends[i].Bind().Send([][]byte{want}, ep, 0); err != nil {
						t.Fatal(err)
					}
					if got := readOne(t, fns[i^1]); !bytes.Equal(want, got) {
						t.Fatal("auto trusted payload corrupted")
					}
				}
				for _, b := range pair.backends {
					if len(b.factory.peers) != 0 {
						t.Fatal("test accidentally used manual pins")
					}
				}
			}
		})
	}
}

// Every proof in this test uses actual host NodePrivate.SealTo/OpenFrom. Only
// TLS exporter values are fixtures so replay/nonce failures are deterministic.
func TestAutoTrustProofReplayReflectionAndRevocation(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	a, b := pair.backends[0], pair.backends[1]
	cs := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h3"}
	clientCS := cs
	clientCS.PeerCertificates = append(clientCS.PeerCertificates, b.factory.cert.Leaf)
	req := &http.Request{Method: "CONNECT", Proto: "connect-ip", URL: automaticPeerURL(b.localNodeKey()), Header: make(http.Header)}
	req.Host = req.URL.Host
	export := func(label string, context []byte, n int) ([]byte, error) {
		h := sha256.Sum256(append([]byte("connection-A"+label), context...))
		return bytes.Clone(h[:]), nil
	}
	wrongExport := func(label string, context []byte, n int) ([]byte, error) {
		h := sha256.Sum256(append([]byte("connection-B"+label), context...))
		return bytes.Clone(h[:]), nil
	}
	value, request, err := a.createNodeRequest(b.localNodeKey(), &cs, req, export)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", value)
	req.Header.Set(serverHintHeader, "?0")
	verified, err := b.verifyNodeRequest(&cs, req, export)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := b.createNodeReply(verified)
	if err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	headers.Set(nodeAuthReply, reply)
	headers.Set(serverHintHeader, "?0")
	if _, err := a.verifyNodeReply(request, &clientCS, headers); err != nil {
		t.Fatal(err)
	}
	if _, err := b.verifyNodeRequest(&cs, req, wrongExport); err == nil {
		t.Fatal("cross-TLS replay accepted")
	}
	altered := request
	altered.nonce[0] ^= 1
	if _, err := a.verifyNodeReply(altered, &clientCS, headers); err == nil {
		t.Fatal("different request nonce accepted")
	}
	bad := headers.Clone()
	bad.Set(serverHintHeader, "?1")
	if _, err := a.verifyNodeReply(request, &clientCS, bad); err == nil {
		t.Fatal("unsigned server hint accepted")
	}
	bad = headers.Clone()
	bad.Add(nodeAuthReply, reply)
	if _, err := a.verifyNodeReply(request, &clientCS, bad); err == nil {
		t.Fatal("duplicate proof accepted")
	}
	if _, err := a.openNodeProof(value, 2); err == nil {
		t.Fatal("request reflected as response")
	}
	fakeCS := clientCS
	fakeCS.PeerCertificates = append(fakeCS.PeerCertificates[:0:0], a.factory.cert.Leaf)
	if _, err := a.verifyNodeReply(request, &fakeCS, headers); err == nil {
		t.Fatal("certificate/channel mismatch accepted")
	}
	originalHost := req.Host
	req.Host = "other.invalid"
	if _, err := b.verifyNodeRequest(&cs, req, export); err == nil {
		t.Fatal("request target rebinding accepted")
	}
	req.Host = originalHost
	var revoked atomic.Bool
	b.host.PeerAllowed = func([32]byte) bool { return !revoked.Load() }
	revoked.Store(true)
	if _, err := b.verifyNodeRequest(&cs, req, export); err == nil {
		t.Fatal("revoked node accepted")
	}
}

func TestAutoTrustRejectsMissingHostKeys(t *testing.T) {
	p := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	if _, err := p.backends[0].factory.New(wgtransport.Host{Bind: p.bases[0], PeerAllowed: func([32]byte) bool { return true }}); err == nil {
		t.Fatal("auto trust without host identity accepted")
	}
	p.backends[1].host.NodeOpen = func([32]byte, [32]byte, []byte) ([]byte, error) { return nil, errors.New("wrong node key") }
	p.open(t)
	remote := p.keys[1].Public().Raw32()
	peer, err := p.backends[0].active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.getSession(); err == nil {
		t.Fatal("wrong node authenticated by TLS cert alone")
	}
	for _, b := range p.backends {
		if b.counters.Connections.Load() != 0 {
			t.Fatal("unauthenticated data session installed")
		}
	}
}
