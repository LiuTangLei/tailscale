// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestHTTP3CapsuleAndDatagramsShareAuthorizationPath(t *testing.T) {
	pair := newTestPair(t, "http3-udp", func(c *Config) { c.InitialPacketSize = 1200 })
	fns := pair.open(t)
	key := pair.keys[1].Public().Raw32()
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(key[:]))
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{7}, 1280)
	if err := pair.backends[0].Bind().Send([][]byte{data}, ep, 0); err != nil {
		t.Fatal(err)
	}
	if got := readOne(t, fns[1]); !bytes.Equal(data, got) {
		t.Fatal("1200-byte initial path did not preserve 1280-byte payload")
	}
	g := pair.backends[0].active.Load()
	g.peersMu.Lock()
	peer := g.peers[key]
	g.peersMu.Unlock()
	peer.mu.Lock()
	session := peer.session
	peer.mu.Unlock()
	channel := session.dgram.(*http3Channel)
	writer := channel.stream.(io.Writer)
	capsuleData := bytes.Repeat([]byte{9}, 1400)
	if err := http3.WriteCapsule(quicvarint.NewWriter(writer), 0, append([]byte{0}, capsuleData...)); err != nil {
		t.Fatal(err)
	}
	if got := readOne(t, fns[1]); !bytes.Equal(capsuleData, got) {
		t.Fatal("capsule data did not enter the same receive path")
	}
	if pair.backends[1].counters.HTTP3Datagrams.Load() < 2 {
		t.Fatal("HTTP datagram counters missing")
	}
}
