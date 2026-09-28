// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"reflect"

	"github.com/LiuTangLei/wireguard-go/conn"
)

// bindAddressCache belongs to one readHost goroutine. Repeated packets from
// the same endpoint can share an immutable wrapper; the endpoint itself keeps
// its original lifetime/semantics. One entry bounds memory, including unknown
// senders. Noncomparable custom Endpoint implementations never reach ==.
type bindAddressCache struct {
	last       conn.Endpoint
	addr       *bindAddr
	comparable bool
}

func (c *bindAddressCache) address(ep conn.Endpoint) *bindAddr {
	if ep == nil {
		return nil
	}
	if c.comparable && ep == c.last {
		return c.addr
	}
	c.last, c.addr = ep, &bindAddr{ep: ep}
	c.comparable = reflect.ValueOf(ep).Comparable()
	return c.addr
}

// Host readers can still enqueue while the QUIC transport is closing. Drain
// only after generation.stop has joined those producers and the QUIC workers.
func (c *bindPacketConn) drainReceiveQueue() {
	for {
		select {
		case r := <-c.rx:
			releasePacket(r.packet)
		default:
			return
		}
	}
}

// Called after receive producers and QUIC workers have stopped. A concurrent
// consumer can take another item, but a channel item and its buffer are owned
// by exactly one taker. Failed/closed transports do not strand pooled packets.
func (g *generation) drainIPReceiveQueue() {
	for {
		select {
		case r := <-g.rx:
			g.rxBytes.Add(-int64(len(r.data)))
			if r.owned != nil {
				releasePacket(r.owned)
			}
		default:
			return
		}
	}
}
