// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package nodeauth provides the bounded, cold-path H3 node handshake. It does
// not encrypt IP packets; those remain protected by QUIC's traffic keys.
package nodeauth

import (
	"errors"

	"github.com/flynn/noise"
	"tailscale.com/types/key"
)

// Handshake is single-owner and must be closed on every success/error path.
// Read/Write switch to Noise transport messages after the two IK messages.
// A responder MUST verify an initiator transport message before authorizing it:
// IK's first message alone is not KCI-resistant responder authentication.
type Handshake interface {
	Read([]byte) ([]byte, error)
	Write([]byte) ([]byte, error)
	Peer() [32]byte
	Close()
}

var ErrHandshake = errors.New("node handshake rejected")

type handshake struct {
	hs        *noise.HandshakeState
	tx, rx    *noise.CipherState
	secret    [32]byte
	peer      [32]byte
	initiator bool
	valid     func([32]byte) bool
	closed    bool
}

// New uses the existing X25519 node identity, with fresh ephemeral keys from
// crypto/rand. valid must recheck the current local identity and authorization;
// zero remote means the responder has not decrypted the initiator identity yet.
func New(k key.NodePrivate, peer [32]byte, initiator bool, binding []byte, valid func([32]byte) bool) (Handshake, error) {
	if k.IsZero() || len(binding) != 32 || valid == nil || !valid(peer) || (initiator && peer == ([32]byte{})) {
		return nil, ErrHandshake
	}
	s := &handshake{secret: k.Raw32(), peer: peer, initiator: initiator, valid: valid}
	pub := k.Public().Raw32()
	cfg := noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s), Pattern: noise.HandshakeIK, Initiator: initiator,
		Prologue: append([]byte("tailscale-h3-node-auth-v2\x00"), binding...), StaticKeypair: noise.DHKey{Private: s.secret[:], Public: pub[:]}}
	if initiator {
		cfg.PeerStatic = peer[:]
	}
	var err error
	s.hs, err = noise.NewHandshakeState(cfg)
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *handshake) Peer() [32]byte { return s.peer }
func (s *handshake) finish(a, b *noise.CipherState) {
	if a == nil {
		return
	}
	s.tx, s.rx = a, b
	if !s.initiator {
		s.tx, s.rx = b, a
	}
	clear(s.hs.LocalEphemeral().Private)
	*s.hs = noise.HandshakeState{}
	s.hs = nil
	clear(s.secret[:])
}
func (s *handshake) Read(msg []byte) ([]byte, error) {
	if s.closed || len(msg) > 4096 || !s.valid(s.peer) {
		return nil, ErrHandshake
	}
	var out []byte
	var err error
	if s.hs != nil {
		var a, b *noise.CipherState
		out, a, b, err = s.hs.ReadMessage(nil, msg)
		if err == nil {
			copy(s.peer[:], s.hs.PeerStatic())
			s.finish(a, b)
		}
	} else {
		out, err = s.rx.Decrypt(nil, nil, msg)
	}
	if err != nil || !s.valid(s.peer) {
		clear(out)
		return nil, ErrHandshake
	}
	return out, nil
}
func (s *handshake) Write(msg []byte) ([]byte, error) {
	if s.closed || len(msg) > 2048 || !s.valid(s.peer) {
		return nil, ErrHandshake
	}
	var out []byte
	var err error
	if s.hs != nil {
		var a, b *noise.CipherState
		out, a, b, err = s.hs.WriteMessage(nil, msg)
		s.finish(a, b)
	} else {
		out, err = s.tx.Encrypt(nil, nil, msg)
	}
	if err != nil || !s.valid(s.peer) {
		clear(out)
		return nil, ErrHandshake
	}
	return out, nil
}
func (s *handshake) Close() {
	if s.hs != nil {
		clear(s.hs.LocalEphemeral().Private)
		*s.hs = noise.HandshakeState{}
		s.hs = nil
	}
	if s.tx != nil {
		*s.tx = noise.CipherState{}
		s.tx = nil
	}
	if s.rx != nil {
		*s.rx = noise.CipherState{}
		s.rx = nil
	}
	clear(s.secret[:])
	s.valid = nil
	s.closed = true
}
