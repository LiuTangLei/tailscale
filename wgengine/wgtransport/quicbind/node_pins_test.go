// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAutoTrustWithExistingExplicitPins(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true })
	fns := pair.open(t)
	for i := range 2 {
		remote := pair.keys[i^1].Public().Raw32()
		p, err := pair.backends[i].active.Load().peer(remote, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.getSession(); err != nil {
			t.Fatal("pinned auto handshake", err)
		}
		ep, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
		if err != nil {
			t.Fatal(err)
		}
		data := bytes.Repeat([]byte{byte(i)}, 512)
		if err := pair.backends[i].Bind().Send([][]byte{data}, ep, 0); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, readOne(t, fns[i^1])) {
			t.Fatal("pinned auto payload mismatch")
		}
	}
}
