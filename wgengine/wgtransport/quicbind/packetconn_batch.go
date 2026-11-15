// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
)

const maxOuterPacketBatch = 32

// The host borrows descriptors only through Send. Reuse the descriptor array
// after all sends return; packet payload ownership stays with packetPool.
var outerBatchBuffers = sync.Pool{New: func() any { return new([maxOuterPacketBatch][]byte) }}

// MaxPacketBatchSize opts this bridge into larger already-paced ready batches.
// Older QUIC libraries continue sending their historical groups of at most 8.
func (*bindPacketConn) MaxPacketBatchSize() int { return maxOuterPacketBatch }

// WritePacketBatch implements quic-go's optional portable batch writer. Every
// input is already one encrypted QUIC UDP packet. No GSO/ECN/DF capability is
// advertised. Forwarding one same-endpoint batch lets magicsock use its own
// correct direct-UDP or relay implementation and retains relay headroom.
func (c *bindPacketConn) WritePacketBatch(input [][]byte, addr net.Addr) error {
	return c.writePacketBatch(nil, input, addr)
}

// WritePacketBatchContext backpressures relay sends without changing the
// existing 32-packet bound or descriptor ownership. Queue Close cancels ctx.
func (c *bindPacketConn) WritePacketBatchContext(ctx context.Context, input [][]byte, addr net.Addr) error {
	return c.writePacketBatch(ctx, input, addr)
}

func (c *bindPacketConn) writePacketBatch(ctx context.Context, input [][]byte, addr net.Addr) error {
	if len(input) == 0 {
		return nil
	}
	if len(input) > maxOuterPacketBatch {
		return errors.New("outer QUIC write batch exceeds bounded capacity")
	}
	if len(input) == 1 {
		_, err := c.writeTo(ctx, input[0], addr)
		return err
	}
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	a, ok := addr.(*bindAddr)
	if !ok || a == nil || a.ep == nil {
		return conn.ErrWrongEndpointType
	}
	c.deadlines.Lock()
	deadline := c.timeWriteDeadline
	c.deadlines.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return deadlineError{}
	}
	var packets [maxOuterPacketBatch]*packetBuffer

	// Validate the entire batch before performing any write.
	for _, p := range input {
		if len(p)+8 > 2048 {
			return errors.New("oversized outer QUIC packet")
		}
	}
	buffers := outerBatchBuffers.Get().(*[maxOuterPacketBatch][]byte)
	defer func() {
		clear(buffers[:]) // don't retain packet storage through descriptors
		outerBatchBuffers.Put(buffers)
		for _, p := range packets {
			if p != nil {
				releasePacket(p)
			}
		}
	}()
	for i, p := range input {
		packet := packetPool.Get().(*packetBuffer)
		packets[i] = packet
		packet.data = packet.small[:8+len(p)]
		copy(packet.data[8:], p)
		buffers[i] = packet.data
	}
	size := min(len(input), c.g.b.host.Bind.BatchSize())
	if size <= 0 {
		return errors.New("invalid host batch size")
	}
	for start := 0; start < len(input); start += size {
		end := min(start+size, len(input))
		err := c.sendHost(ctx, buffers[start:end], a.ep)
		if err != nil {
			return err
		}
		var bytes uint64
		for _, p := range input[start:end] {
			bytes += uint64(len(p))
		}
		c.g.b.counters.RawBytesSent.Add(bytes)
		c.g.b.counters.RawWriteBatches.Add(1)
		c.g.b.counters.RawBatchPackets.Add(uint64(end - start))
	}
	return nil
}

func (c *bindPacketConn) sendHost(ctx context.Context, packets [][]byte, ep conn.Endpoint) error {
	if ctx != nil {
		c.deadlines.Lock()
		deadline := c.timeWriteDeadline
		c.deadlines.Unlock()
		if !deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if sender, ok := c.g.b.host.Bind.(interface {
			SendWithContext(context.Context, [][]byte, conn.Endpoint, int) error
		}); ok {
			return sender.SendWithContext(ctx, packets, ep, 8)
		}
	}
	return c.g.b.host.Bind.Send(packets, ep, 8)
}
