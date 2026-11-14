// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Every connection starts with packets of initial_packet_size, which any path
// carries. After the handshake QUIC probes max_packet_size and uses it once a
// probe has been acknowledged; if the path later stops carrying it, QUIC
// returns to the initial size by itself. The default lets one datagram hold a
// full 1280-byte tunnel packet, in a UDP payload 8 bytes larger than the one
// WireGuard uses for the same packet.
//
// IP packets never depend on the outcome: one that does not fit a datagram is
// fragmented by the carrier. The size matters for efficiency only, and that
// is decided when a TCP connection is opened, by the MSS it negotiates.
const defaultMaxPacketSize = 1320

// packetSizeHeader states the sender's max_packet_size, optionally followed by
// the size its previous connection to this peer reached ("1320,1320").
const packetSizeHeader = "Tailnet-Packet-Size"

// provenPacketGrace is how long a new connection may assume the packet size
// the previous one reached, while its own probe is still on the way.
const provenPacketGrace = 5 * time.Second

func packetSizeValue(max, proven uint16) string {
	if proven == 0 {
		return strconv.Itoa(int(max))
	}
	return strconv.Itoa(int(max)) + "," + strconv.Itoa(int(proven))
}

// parsePacketSize returns zeros for a peer that states nothing usable; such a
// peer keeps sending packets of the initial size.
func parsePacketSize(h http.Header) (max, proven uint16) {
	values := h.Values(packetSizeHeader)
	if len(values) != 1 {
		return 0, 0
	}
	first, second, both := strings.Cut(values[0], ",")
	size := func(s string) uint16 {
		n, err := strconv.ParseUint(s, 10, 16)
		if err != nil || n < 1200 || n > 1452 {
			return 0
		}
		return uint16(n)
	}
	max = size(first)
	if max == 0 {
		return 0, 0
	}
	if both {
		if proven = size(second); proven > max {
			proven = 0
		}
	}
	return max, proven
}

// tcpPacketSize is the packet size to assume for a TCP connection that is
// being opened through s. The MSS in a SYN limits what the other end of that
// TCP connection sends, and those segments arrive in the peer's packets: the
// answer is therefore bounded by what the peer said it uses, and otherwise
// taken from this end of the same path.
func (p *peer) tcpPacketSize(s *session) uint16 {
	cfg := &p.g.b.factory.cfg
	base := cfg.InitialPacketSize
	limit := min(uint16(s.peerPacketSize.Load()), cfg.MaxPacketSize)
	if limit <= base {
		return base
	}
	size := uint16(min(s.q.PacketSize(), int(limit)))
	if size < limit && time.Since(s.created) < provenPacketGrace {
		// The probe of this connection has not been answered yet. If the
		// last connection reached a larger size, a TCP connection opened now
		// should not be held to the small one for its whole life. Should the
		// probe fail after all, its packets are fragmented, not lost.
		size = max(size, min(uint16(s.provenPacketSize.Load()), limit))
	}
	return max(size, base)
}

// notePacketSize remembers, per peer, the packet size an outgoing connection
// reached. The next connection states it to the peer and assumes it briefly.
func (p *peer) notePacketSize(s *session, now time.Time) {
	if !s.outgoing {
		return
	}
	size := uint32(s.q.PacketSize())
	if size <= uint32(p.g.b.factory.cfg.InitialPacketSize) {
		if now.Sub(s.created) < 2*provenPacketGrace {
			return // not known yet
		}
		size = 0
	}
	if s.notedPacketSize.Swap(size+1) != size+1 {
		p.g.b.clientSessionCache(p.cfg.key).packetSize.Store(size)
	}
}

// usePacketSize applies the peer's answer to an outgoing session.
func (c *peerSessionCache) usePacketSize(s *session, answer http.Header) {
	peerMax, _ := parsePacketSize(answer)
	c.peerPacketSize.Store(uint32(peerMax))
	s.peerPacketSize.Store(uint32(peerMax))
	s.provenPacketSize.Store(c.packetSize.Load())
}
