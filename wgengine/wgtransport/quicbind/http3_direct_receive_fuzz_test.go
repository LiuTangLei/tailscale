// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
)

func FuzzDirectHTTPDatagramFraming(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {0, 0, 0x45, 1}, {0, 2, 1}, {0x40, 0, 0x40, 0, 0x60}, {0xff, 0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c := &http3Channel{g: &generation{b: &Backend{}}}
		before := bytes.Clone(data)
		var got []byte
		h := c.directIPDatagramHandler(0, func(b []byte) { got = bytes.Clone(b) })
		handled := h(data)
		if !bytes.Equal(data, before) {
			t.Fatal("receiver mutated QUIC-owned packet")
		}
		if !handled {
			return
		}
		id, n, err := quicvarint.Parse(data)
		if err != nil || id != 0 {
			t.Fatal("wrong request intercepted")
		}
		context, m, err := quicvarint.Parse(data[n:])
		if err != nil || context != 0 || len(got) == 0 || len(got) > maxPacket || !bytes.Equal(got, data[n+m:]) {
			t.Fatal("invalid context or payload intercepted")
		}
	})
}
