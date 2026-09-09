// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"errors"
	"net"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
)

// WritePacketBatch implements quic-go's optional portable batch writer. Every
// input is already one encrypted QUIC UDP packet. No GSO/ECN/DF capability is
// advertised. Forwarding one same-endpoint batch lets magicsock use its own
// correct direct-UDP or relay implementation and retains relay headroom.
func (c *bindPacketConn) WritePacketBatch(input [][]byte, addr net.Addr) error {
	if len(input) == 0 {
		return nil
	}
	if len(input) > 8 {
		return errors.New("outer QUIC write batch exceeds bounded capacity")
	}
	if len(input) == 1 {
		_, err := c.WriteTo(input[0], addr)
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
	var packets [8]*packetBuffer
	var buffers [8][]byte
	// Validate the entire batch before performing any write.
	for _, p := range input {
		if len(p)+8 > 2048 {
			return errors.New("oversized outer QUIC packet")
		}
	}
	defer func() {
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
		if err := c.g.b.host.Bind.Send(buffers[start:end], a.ep, 8); err != nil {
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
