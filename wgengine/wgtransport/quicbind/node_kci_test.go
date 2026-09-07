// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/flynn/noise"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgtransport/nodeauth"
)

// This adversary has the victim's copied private key, the claimed node's
// PUBLIC key, and its own ephemeral/TLS keys. It has no claimed-node private
// key. Grant it the exact static-static DH oracle which broke v1, including a
// valid forged IK initiation, but not the missing ephemeral-static DH.
type kciDH struct {
	noise.DHFunc
	victimPrivate, victimPublic, claimedPublic [32]byte
	forged                                     *atomic.Int64
}

func (d kciDH) DH(private, public []byte) ([]byte, error) {
	if bytes.Equal(private, make([]byte, 32)) {
		if bytes.Equal(public, d.victimPublic[:]) {
			d.forged.Add(1)
			return d.DHFunc.DH(d.victimPrivate[:], d.claimedPublic[:])
		}
		return nil, errors.New("attacker lacks claimed static private key")
	}
	return d.DHFunc.DH(private, public)
}

type kciHandshake struct {
	hs        *noise.HandshakeState
	tx, rx    *noise.CipherState
	initiator bool
	remote    [32]byte
	replyRead *atomic.Int64
}

func (h *kciHandshake) split(a, b *noise.CipherState) {
	if a != nil {
		h.tx, h.rx = a, b
		if !h.initiator {
			h.tx, h.rx = b, a
		}
		h.hs = nil
	}
}
func (h *kciHandshake) Read(b []byte) ([]byte, error) {
	if h.initiator && h.replyRead != nil {
		h.replyRead.Add(1)
	}
	if h.hs == nil {
		return h.rx.Decrypt(nil, nil, b)
	}
	out, a, c, err := h.hs.ReadMessage(nil, b)
	if err == nil {
		copy(h.remote[:], h.hs.PeerStatic())
		h.split(a, c)
	}
	return out, err
}
func (h *kciHandshake) Write(b []byte) ([]byte, error) {
	if h.hs == nil {
		return h.tx.Encrypt(nil, nil, b)
	}
	out, a, c, err := h.hs.WriteMessage(nil, b)
	if err == nil {
		h.split(a, c)
	}
	return out, err
}
func (h *kciHandshake) Peer() [32]byte { return h.remote }
func (h *kciHandshake) Close()         { h.hs = nil; h.tx = nil; h.rx = nil }

func TestAutoTrustKCIRejectedInBothTLSRoles(t *testing.T) {
	for _, attackerInitiates := range []bool{false, true} {
		t.Run(map[bool]string{false: "fake_responder", true: "forged_initiation_requires_finished"}[attackerInitiates], func(t *testing.T) {
			pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
			victim, impostor := pair.backends[0], pair.backends[1]
			victimKey := pair.keys[0]
			victimPub, claimedPub := victimKey.Public().Raw32(), pair.keys[1].Public().Raw32()
			pair.keys[1] = key.NodePrivate{} // Never available to the adversary or callbacks.
			victim.host.NodeHandshake = func(local, remote [32]byte, initiator bool, binding []byte) (nodeauth.Handshake, error) {
				return nodeauth.New(victimKey, remote, initiator, binding, func(remote [32]byte) bool {
					return local == victimPub && (remote == ([32]byte{}) || remote == claimedPub)
				})
			}
			victim.host.PeerAllowed = func(k [32]byte) bool { return k == claimedPub }
			impostor.host.NodePublic = func() [32]byte { return claimedPub }
			var forged, replyRead atomic.Int64
			impostor.host.NodeHandshake = func(local, remote [32]byte, initiator bool, binding []byte) (nodeauth.Handshake, error) {
				dh := kciDH{noise.DH25519, victimKey.Raw32(), victimPub, claimedPub, &forged}
				cfg := noise.Config{CipherSuite: noise.NewCipherSuite(dh, noise.CipherChaChaPoly, noise.HashBLAKE2s), Pattern: noise.HandshakeIK, Initiator: initiator,
					StaticKeypair: noise.DHKey{Private: make([]byte, 32), Public: claimedPub[:]}, Prologue: append([]byte("tailscale-h3-node-auth-v2\x00"), binding...)}
				if initiator {
					cfg.PeerStatic = remote[:]
				}
				hs, err := noise.NewHandshakeState(cfg)
				return &kciHandshake{hs: hs, initiator: initiator, remote: remote, replyRead: &replyRead}, err
			}
			pair.open(t)
			caller, remote := victim, claimedPub
			if attackerInitiates {
				caller, remote = impostor, victimPub
			}
			p, err := caller.active.Load().peer(remote, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.getSession(); err == nil {
				t.Fatal("victim private key authorized another node")
			}
			if attackerInitiates && (forged.Load() == 0 || replyRead.Load() == 0) {
				t.Fatal("test did not exercise an accepted forged IK initiation and provisional response")
			}
			for _, b := range pair.backends {
				if b.counters.Connections.Load() != 0 {
					t.Fatal("provisional handshake installed an IP session")
				}
			}
		})
	}
}
