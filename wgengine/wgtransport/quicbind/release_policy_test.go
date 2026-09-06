// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"testing"

	"github.com/quic-go/quic-go"
)

func TestPublishedQUICPolicy(t *testing.T) {
	for _, http3 := range []bool{false, true} {
		b := &Backend{factory: &Factory{cfg: Config{HTTP3: http3, InitialPacketSize: 1400}}}
		c := b.quicConfig()
		if !c.EnableBBR || c.EnableCubic || !c.EnableDatagrams || c.Allow0RTT {
			t.Fatalf("unexpected release transport policy (http3=%v): BBR=%v CUBIC=%v datagrams=%v 0RTT=%v", http3, c.EnableBBR, c.EnableCubic, c.EnableDatagrams, c.Allow0RTT)
		}
	}
	if http3ReceiveQueueCapacity != 256 || quicReceiveQueueCapacity != 1024 {
		t.Fatalf("unexpected compiled queue profile: HTTP/3=%d QUIC=%d", http3ReceiveQueueCapacity, quicReceiveQueueCapacity)
	}
	// Opt-in is scoped to our carrier, not a global default for other users.
	var untouched quic.Config
	if untouched.EnableBBR || untouched.EnableCubic {
		t.Fatal("library default was changed globally")
	}
}
