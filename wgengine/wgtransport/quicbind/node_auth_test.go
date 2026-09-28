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
	"strings"
	"testing"

	"tailscale.com/wgengine/wgtransport"
	"tailscale.com/wgengine/wgtransport/nodeauth"
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

// Each negative case starts a fresh handshake, so rejection cannot be an
// artifact of trying to reuse an already-consumed Noise state.
func TestAutoTrustProofReplayReflectionAndRevocation(t *testing.T) {
	for _, name := range []string{"valid", "valid-secret", "wrong-secret", "client-secret-only", "server-secret-only", "exporter-with-secret", "exporter", "target", "old-scheme", "identity-privacy", "request-hint", "revoked", "nonce", "reply-hint", "duplicate", "reflection", "certificate"} {
		t.Run(name, func(t *testing.T) {
			pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
			a, b := pair.backends[0], pair.backends[1]
			switch name {
			case "valid-secret", "wrong-secret", "exporter-with-secret":
				a.factory.cfg.AuthenticationSecret = [32]byte{1}
				b.factory.cfg.AuthenticationSecret = [32]byte{1}
			case "client-secret-only":
				a.factory.cfg.AuthenticationSecret = [32]byte{1}
			case "server-secret-only":
				b.factory.cfg.AuthenticationSecret = [32]byte{1}
			}
			if name == "wrong-secret" {
				b.factory.cfg.AuthenticationSecret = [32]byte{2}
			}
			cs := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "h3"}
			clientCS := cs
			clientCS.PeerCertificates = append(clientCS.PeerCertificates, b.factory.cert.Leaf)
			req := &http.Request{Method: "CONNECT", Proto: "connect-ip", URL: automaticPeerURL(b.localNodeKey()), Header: make(http.Header)}
			req.Host = req.URL.Host
			export := func(label string, context []byte, n int) ([]byte, error) {
				h := sha256.Sum256(append([]byte("connection-A"+label), context...))
				return bytes.Clone(h[:]), nil
			}
			value, request, err := a.createNodeRequest(b.localNodeKey(), &cs, req, export)
			if err != nil {
				t.Fatal(err)
			}
			defer request.handshake.Close()
			req.Header.Set("Authorization", value)
			req.Header.Set(serverHintHeader, "?0")
			if name == "identity-privacy" {
				raw, err := decodeNodeMessage(value)
				if err != nil {
					t.Fatal(err)
				}
				local := a.localNodeKey()
				if bytes.Contains(raw, local[:]) || strings.Contains(value, hex.EncodeToString(local[:])) || req.Header.Get("X-Tailnet-Pinned-Proof") != "" {
					t.Fatal("initiator static identity exposed")
				}
			}
			switch name {
			case "exporter", "exporter-with-secret":
				export = func(string, []byte, int) ([]byte, error) { return make([]byte, 32), nil }
			case "target":
				req.Host = "other.invalid"
			case "old-scheme":
				req.Header.Set("Authorization", "TailnetNode "+strings.TrimPrefix(value, nodeAuthScheme))
			case "request-hint":
				req.Header.Set(serverHintHeader, "?1")
			case "revoked":
				b.host.PeerAllowed = func([32]byte) bool { return false }
			}
			verified, err := b.verifyNodeRequest(&cs, req, export)
			switch name {
			case "exporter", "exporter-with-secret", "wrong-secret", "client-secret-only", "server-secret-only", "target", "old-scheme", "request-hint", "revoked":
				if err == nil {
					verified.handshake.Close()
					t.Fatal("invalid request accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer verified.handshake.Close()
			if name == "nonce" {
				verified.nonce[0] ^= 1
			}
			reply, err := b.createNodeReply(verified)
			if err != nil {
				t.Fatal(err)
			}
			headers := make(http.Header)
			headers.Set(nodeAuthReply, reply)
			headers.Set(serverHintHeader, "?0")
			switch name {
			case "reply-hint":
				headers.Set(serverHintHeader, "?1")
			case "duplicate":
				headers.Add(nodeAuthReply, reply)
			case "reflection":
				headers.Set(nodeAuthReply, value)
			case "certificate":
				clientCS.PeerCertificates = append(clientCS.PeerCertificates[:0:0], a.factory.cert.Leaf)
			}
			_, err = a.verifyNodeReply(request, &clientCS, headers)
			if name != "valid" && name != "valid-secret" && name != "identity-privacy" {
				if err == nil {
					t.Fatal("invalid reply accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var wire bytes.Buffer
			if err := writeNodeFinished(&wire, request.handshake, "initiator finished v2"); err != nil {
				t.Fatal(err)
			}
			if err := readNodeFinished(&wire, verified.handshake, "initiator finished v2"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAutoTrustRejectsMissingHostKeys(t *testing.T) {
	p := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	if _, err := p.backends[0].factory.New(wgtransport.Host{Bind: p.bases[0], PeerAllowed: func([32]byte) bool { return true }}); err == nil {
		t.Fatal("auto trust without host identity accepted")
	}
	p.backends[1].host.NodeHandshake = func([32]byte, [32]byte, bool, []byte) (nodeauth.Handshake, error) {
		return nil, errors.New("wrong node key")
	}
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
