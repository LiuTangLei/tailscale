// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"errors"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type datagramBatchSender interface {
	SendDatagramsWithPrefix([]byte, [][]byte) (int, error)
}

// Published dependencies without the optional API keep their existing path.
// Experimental builds report this capability explicitly in diagnostics.
var ipBatchSupported = func() bool {
	_, ok := any((*http3.Stream)(nil)).(datagramBatchSender)
	return ok
}()

// sendIPBatch keeps the caller's ready TUN batch intact across the H3 queue
// boundary. It applies only to native IP, never waits to form a batch, and
// never changes wire framing.
// Caller owns sendMu. Each bounded group rechecks current authorization before
// enqueue; all actual data is copied into QUIC-owned buffers before return.
func (p *peer) sendIPBatch(s *session, bufs [][]byte, offset int) (handled bool, err error) {
	h3, ok := s.dgram.(*http3Channel)
	if !ok {
		return false, nil
	}
	sender, ok := h3.stream.(datagramBatchSender)
	if !ok {
		return false, nil
	}
	var payloads [32][]byte
	for len(bufs) > 0 {
		count := min(len(bufs), len(payloads))
		for i, b := range bufs[:count] {
			if !p.stampValid(s.stamp) {
				return true, ErrUnknownPeer
			}
			payloads[i] = b[offset:]
		}
		p.touch()
		n, sendErr := sender.SendDatagramsWithPrefix([]byte{0}, payloads[:count])
		if n < 0 || n > count {
			return true, errors.New("invalid H3 datagram batch result")
		}
		if n > 0 {
			p.g.b.counters.SentPackets.Add(uint64(n))
			p.g.b.counters.FastPackets.Add(uint64(n))
			p.g.b.counters.IPBatchCalls.Add(1)
			p.g.b.counters.IPBatchPackets.Add(uint64(n))
		}
		var tooLarge *quic.DatagramTooLargeError
		if n == 0 && errors.As(sendErr, &tooLarge) {
			// An exceptional MTU/fragmented group retains the original per-packet
			// path. The queue validates ALL lengths before accepting any frame.
			for _, b := range bufs[:count] {
				if err := p.sendPacket(s, b[offset:], p.scratch[:]); err != nil {
					return true, err
				}
				p.g.b.counters.FastPackets.Add(1)
			}
		} else if sendErr != nil {
			return true, sendErr
		} else if n != count {
			return true, errors.New("short H3 datagram batch without error")
		}
		clear(payloads[:count])
		bufs = bufs[count:]
	}
	return true, nil
}
