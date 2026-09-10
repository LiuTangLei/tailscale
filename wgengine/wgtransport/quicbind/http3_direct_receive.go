// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

type datagramReceiveSetter interface {
	SetDatagramReceiveHandler(func([]byte) bool) error
}

// StartDirectIPDatagrams runs only after CONNECT-IP authentication and session
// installation. Only raw IP from that exact HTTP request is intercepted.
// Fragments, capsules and other HTTP streams retain their existing receiver.
// The callback borrows payload bytes and must not block the QUIC event loop.
func (c *http3Channel) StartDirectIPDatagrams(receive func([]byte)) bool {
	if c.g.b.factory.cfg.TCPStreams {
		return false
	}
	setter, ok := any(c.q).(datagramReceiveSetter)
	if !ok {
		return false
	}
	identified, ok := c.stream.(interface{ StreamID() quic.StreamID })
	if !ok || identified.StreamID() < 0 || identified.StreamID()%4 != 0 {
		return false
	}
	handler := c.directIPDatagramHandler(uint64(identified.StreamID())/4, receive)
	if err := setter.SetDatagramReceiveHandler(handler); err != nil {
		return false
	}
	c.g.b.counters.DirectReceiveConnections.Add(1)
	return true
}

func (c *http3Channel) directIPDatagramHandler(quarterStreamID uint64, receive func([]byte)) func([]byte) bool {
	return func(data []byte) bool {
		id, n, err := quicvarint.Parse(data)
		if err != nil || id != quarterStreamID {
			return false
		}
		contextID, m, err := quicvarint.Parse(data[n:])
		if err != nil || contextID != 0 {
			return false
		}
		payload := data[n+m:]
		if len(payload) == 0 || len(payload) > maxPacket {
			return false
		}
		c.g.b.counters.HTTP3Datagrams.Add(1)
		c.g.b.counters.DirectReceiveDatagrams.Add(1)
		receive(payload)
		return true
	}
}

// queueDirectIP accepts bytes from an already-authenticated connection into a
// bounded, generation-stamped queue. It MUST NOT call host policy from QUIC's
// event loop: policy may take a control-plane mutex. generation.receivePackets
// performs the existing live stampValid check before returning bytes, and the
// IP device still performs current peer/source/ACL checks before TUN delivery.
// Thus an old cached grant never authorizes data and revocation stays live.
func (p *peer) queueDirectIP(s *session, borrowed []byte) {
	if s.q.Context().Err() != nil || !p.stampCurrent(s.stamp) {
		return
	}
	p.touch()
	if p.g.rxBytes.Add(int64(len(borrowed))) > packetBudget {
		p.g.rxBytes.Add(-int64(len(borrowed)))
		p.g.b.counters.ReceiveQueueDrops.Add(1)
		return
	}
	owned := bytes.Clone(borrowed)
	select {
	case p.g.rx <- received{data: owned, ep: p.ep.Load(), peer: p, stamp: s.stamp}:
		p.g.b.counters.ReceivedPackets.Add(1)
	case <-p.g.ctx.Done():
		p.g.rxBytes.Add(-int64(len(owned)))
	default:
		p.g.rxBytes.Add(-int64(len(owned)))
		p.g.b.counters.ReceiveQueueDrops.Add(1)
	}
}
