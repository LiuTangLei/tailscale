// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"bytes"
	"sync/atomic"
	"tailscale.com/types/key"
	"testing"
)

func TestTransportNodeKeyCallbacksRevocationAndRotation(t *testing.T) {
	a, b := new(userspaceEngine), new(userspaceEngine)
	ka, kb := key.NewNode(), key.NewNode()
	pa, pb := ka.Public(), kb.Public()
	a.packetPrivate.Store(&ka)
	a.packetIdentity.Store(&pa)
	b.packetPrivate.Store(&kb)
	b.packetIdentity.Store(&pb)
	var allowed atomic.Bool
	allowed.Store(true)
	a.packetPolicy.Store(&packetPolicy{peer: func(local, peer key.NodePublic) bool { return allowed.Load() && local == pa && peer == pb }})
	b.packetPolicy.Store(&packetPolicy{peer: func(local, peer key.NodePublic) bool { return allowed.Load() && local == pb && peer == pa }})
	data := []byte("connection-bound H3 proof")
	binding := make([]byte, 32)
	initiator, err := a.transportNodeHandshake(pa.Raw32(), pb.Raw32(), true, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	responder, err := b.transportNodeHandshake(pb.Raw32(), [32]byte{}, false, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	ciphertext, err := initiator.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := responder.Read(ciphertext)
	if err != nil || !bytes.Equal(plaintext, data) {
		t.Fatal("proof failed", err)
	}
	allowed.Store(false)
	if _, err := initiator.Write(data); err == nil {
		t.Fatal("revoked peer seal accepted")
	}
	if _, err := responder.Write(data); err == nil {
		t.Fatal("revoked peer open accepted")
	}
	allowed.Store(true)
	next := key.NewNode()
	nextPublic := next.Public()
	a.packetPrivate.Store(&next)
	a.packetIdentity.Store(&nextPublic)
	if _, err := initiator.Write(data); err == nil {
		t.Fatal("stale expected local key accepted")
	}
	a.packetPrivate.Store(nil)
	if _, err := a.transportNodeHandshake(nextPublic.Raw32(), pb.Raw32(), true, binding); err == nil {
		t.Fatal("stopped node accepted")
	}
}
