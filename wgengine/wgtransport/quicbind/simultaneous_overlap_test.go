// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"
)

// A peer can send its first datagram on an authenticated connection before
// both ends agree which of two crossed connections wins. The losing connection
// must be drained for the bounded overlap, not torn down with its first packet.
func TestHTTP3LosingConnectionDrainsAuthenticatedDatagrams(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true })
	for _, backend := range pair.backends {
		backend.timing.overlap = 750 * time.Millisecond
	}
	receive := pair.open(t)
	preferred := 0
	if pair.keys[0].Public().Compare(pair.keys[1].Public()) > 0 {
		preferred = 1
	}
	other := preferred ^ 1
	var peers [2]*peer
	for i := range peers {
		remote := pair.keys[i^1].Public().Raw32()
		if _, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(remote[:])); err != nil {
			t.Fatal(err)
		}
		var err error
		peers[i], err = pair.backends[i].active.Load().peer(remote, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	primary, err := peers[preferred].getSessionContext(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Complete a payload round trip so both actors have installed the winner.
	for i := range peers {
		remote := pair.keys[i^1].Public().Raw32()
		endpoint, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
		if err != nil {
			t.Fatal(err)
		}
		if err := pair.backends[i].Bind().Send([][]byte{{42, 43, 44}}, endpoint, 0); err != nil {
			t.Fatal(err)
		}
		readOne(t, receive[i^1])
	}
	peers[other].mu.Lock()
	remotePrimary := peers[other].session
	peers[other].mu.Unlock()
	candidate, err := peers[other].getSessionContext(ctx, remotePrimary)
	if err != nil || candidate == nil || candidate.q == remotePrimary.q {
		t.Fatalf("authenticated crossed connection was closed instead of drained: candidate=%v err=%v", candidate != nil, err)
	}
	payload := []byte("first datagram already sent before crossed-dial arbitration")
	if err := candidate.dgram.SendDatagram(append([]byte{frameRaw}, payload...)); err != nil {
		t.Fatalf("early authenticated datagram dropped: %v", err)
	}
	if got := readOne(t, receive[preferred]); !bytes.Equal(got, payload) {
		t.Fatal("overlap payload changed")
	}
	for i, want := range []*session{primary, remotePrimary} {
		index := preferred
		if i == 1 {
			index = other
		}
		peers[index].mu.Lock()
		got := peers[index].session
		peers[index].mu.Unlock()
		if got != want || got.q.Context().Err() != nil {
			t.Fatal("draining a loser replaced or closed the established winner")
		}
	}
	select {
	case <-candidate.q.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("losing connection outlived the bounded overlap")
	}
	if primary.q.Context().Err() != nil || remotePrimary.q.Context().Err() != nil {
		t.Fatal("retiring the loser also killed the winner")
	}
}
