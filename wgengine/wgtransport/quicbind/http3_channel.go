// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync/atomic"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type http3Channel struct {
	client *http3.ClientConn // immutable, non-nil on an outgoing authenticated tunnel
	tcpStreams bool // authenticated peer advertised CONNECT byte streams
	g               *generation
	q               *quic.Conn
	stream          datagramChannel
	fragments       bool
	capsules        io.Reader
	capsulesStarted atomic.Bool
}

func newHTTP3Channel(g *generation, q *quic.Conn, str datagramChannel, capsules io.Reader, fragments bool) *http3Channel {
	return &http3Channel{g: g, q: q, stream: str, fragments: fragments, capsules: capsules}
}

// Capsules are the uncommon side channel. Normal packets are read directly
// from the HTTP/3 stream by the session receiver, with no extra queue/copy or
// per-packet goroutine handoff. Start only after the session is installed.
func (c *http3Channel) StartCapsules(deliver func([]byte)) {
	if c.capsulesStarted.Swap(true) {
		return
	}
	c.g.workers.Add(1)
	go func() { defer c.g.workers.Done(); c.readCapsules(c.capsules, deliver) }()
}
func (c *http3Channel) fail() {
	_ = c.q.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeMessageError), "CONNECT-IP stream closed")
}
func (c *http3Channel) normalize(b []byte) []byte {
	// HTTP/3 has already removed the Quarter Stream ID. Convert context IDs to
	// the carrier's private framing only after explicit extension negotiation.
	contextID, n, err := quicvarint.Parse(b)
	if err != nil {
		c.g.b.counters.MalformedFrames.Add(1)
		return nil
	}
	if contextID != 0 && (contextID != 2 || !c.fragments) {
		return nil
	}
	if n != 1 {
		// Nonminimal varints are legal; normalize the leading byte without copying.
		b = b[n-1:]
	}
	if contextID == 0 {
		b[0] = frameRaw
	} else {
		b[0] = frameFragment
	}
	if len(b) > maxPacket+fragmentHeader {
		c.g.b.counters.ReceiveQueueDrops.Add(1)
		return nil
	}
	c.g.b.counters.HTTP3Datagrams.Add(1)
	return b
}
func (c *http3Channel) readCapsules(r io.Reader, deliver func([]byte)) {
	parser := http3.NewCapsuleParser(r)
	for {
		kind, body, err := parser.Next()
		if err != nil {
			c.fail()
			return
		}
		if body.Remaining() > maxPacket+fragmentHeader {
			c.fail()
			return
		}
		switch kind {
		case 0: // RFC 9297 DATAGRAM capsule. Receive support is required even when
			// we send normal traffic exclusively with unreliable QUIC DATAGRAMs.
			b, err := io.ReadAll(body)
			if err != nil {
				c.fail()
				return
			}
			if frame := c.normalize(b); frame != nil {
				deliver(frame)
			}
		case 1, 2, 3: // RFC 9484 address/route capsules: syntax check, never authority.
			b, err := io.ReadAll(body)
			if err != nil || validateIPCapsule(uint64(kind), b) != nil {
				c.fail()
				return
			}
		default:
			// RFC 9297 extensibility: unknown types are ignored, not interpreted.
			if err := body.Discard(); err != nil {
				c.fail()
				return
			}
		}
	}
}
func (c *http3Channel) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		b, err := c.stream.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		if frame := c.normalize(b); frame != nil {
			return frame, nil
		}
	}
}
func (c *http3Channel) SendDatagram(b []byte) error {
	if len(b) == 0 {
		return errors.New("empty IP datagram")
	}
	if b[0] == frameFragment {
		if !c.fragments {
			return errors.New("CONNECT-IP peer did not negotiate IP fragmentation")
		}
		b[0] = 2
		defer func() { b[0] = frameFragment }()
	}
	err := c.stream.SendDatagram(b)
	var sizeErr *quic.DatagramTooLargeError
	if errors.As(err, &sizeErr) {
		// Reserve the largest Quarter Stream ID. This bound also works when the
		// underlying HTTP implementation reports its pre-prefix QUIC limit.
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: max(1, sizeErr.MaxDatagramPayloadSize-8)}
	}
	return err
}

// Address assignments and advertised routes do NOT update Tailnet policy.
// Peers are already configured by the authenticated control plane; validate
// capsules so malformed input is not mistaken for an accepted assignment.
func validateIPCapsule(kind uint64, b []byte) error {
	var prevStart, prevEnd netip.Addr
	var prevProto byte
	entries := 0
	for len(b) > 0 {
		entries++
		if entries > 1024 {
			return errors.New("too many IP capsule entries")
		}
		if kind == 1 || kind == 2 {
			_, n, err := quicvarint.Parse(b)
			if err != nil {
				return err
			}
			b = b[n:]
		}
		if len(b) < 1 {
			return io.ErrUnexpectedEOF
		}
		version := b[0]
		b = b[1:]
		n := 0
		switch version {
		case 4:
			n = 4
		case 6:
			n = 16
		default:
			return errors.New("invalid IP version in capsule")
		}
		if kind == 1 || kind == 2 {
			if len(b) < n+1 {
				return io.ErrUnexpectedEOF
			}
			if int(b[n]) > 8*n {
				return errors.New("invalid capsule prefix length")
			}
			b = b[n+1:]
			continue
		}
		if len(b) < 2*n+1 {
			return io.ErrUnexpectedEOF
		}
		start, _ := netip.AddrFromSlice(b[:n])
		end, _ := netip.AddrFromSlice(b[n : 2*n])
		proto := b[2*n]
		b = b[2*n+1:]
		if start.Compare(end) > 0 {
			return errors.New("inverted capsule address range")
		}
		if prevStart.IsValid() {
			if start.BitLen() < prevStart.BitLen() || (start.BitLen() == prevStart.BitLen() && (proto < prevProto || (proto == prevProto && start.Compare(prevEnd) <= 0))) {
				return errors.New("unsorted or overlapping capsule routes")
			}
		}
		prevStart, prevEnd, prevProto = start, end, proto
	}
	return nil
}
