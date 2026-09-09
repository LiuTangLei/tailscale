// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
)

// bindAddr deliberately keeps the ORIGINAL host Endpoint. Converting its
// DstToString into an IP would break Tailscale's node-key addressing and DERP.
type bindAddr struct{ ep conn.Endpoint }

func (a *bindAddr) Network() string { return "magicsock" }
func (a *bindAddr) String() string  { return a.ep.DstToString() }

type localBindAddr struct{ port uint16 }

func (a localBindAddr) Network() string { return "magicsock" }
func (a localBindAddr) String() string  { return "magicsock" }

type rawPacket struct {
	packet *packetBuffer
	addr   *bindAddr
}
type bindPacketConn struct {
	g                               *generation
	rx                              chan rawPacket
	done                            chan struct{}
	once                            sync.Once
	deadlines                       sync.Mutex
	readDeadline, timeWriteDeadline time.Time
	changed                         chan struct{}
}

func newBindPacketConn(g *generation) *bindPacketConn {
	return &bindPacketConn{g: g, rx: make(chan rawPacket, 2048), done: make(chan struct{}), changed: make(chan struct{})}
}
func (c *bindPacketConn) LocalAddr() net.Addr { return localBindAddr{c.g.port} }

// Socket buffers belong to magicsock (or to the externally supplied packet
// socket configured by Backend.Open), not to this logical peer PacketConn.
// A per-QUIC-connection request must not resize a shared socket or warn that
// this in-memory adapter is an unconfigured UDP socket.
func (c *bindPacketConn) SetReadBuffer(int) error  { return nil }
func (c *bindPacketConn) SetWriteBuffer(int) error { return nil }
func (c *bindPacketConn) Close() error             { c.once.Do(func() { close(c.done) }); return nil }
func (c *bindPacketConn) SetDeadline(t time.Time) error {
	c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}
func (c *bindPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.Lock()
	c.readDeadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	c.deadlines.Unlock()
	return nil
}
func (c *bindPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.Lock()
	c.timeWriteDeadline = t
	c.deadlines.Unlock()
	return nil
}
func (c *bindPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		c.deadlines.Lock()
		deadline := c.readDeadline
		changed := c.changed
		c.deadlines.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, &net.OpError{Op: "read", Net: "magicsock", Err: deadlineError{}}
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var r rawPacket
		select {
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, nil, &net.OpError{Op: "read", Net: "magicsock", Err: deadlineError{}}
		case r = <-c.rx:
		}
		if timer != nil {
			timer.Stop()
		}
		if len(r.packet.data) > len(buf) {
			releasePacket(r.packet)
			continue
		}
		n := copy(buf, r.packet.data)
		releasePacket(r.packet)
		return n, r.addr, nil
	}
}
func (c *bindPacketConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	a, ok := addr.(*bindAddr)
	if !ok || a == nil || a.ep == nil {
		return 0, conn.ErrWrongEndpointType
	}
	c.deadlines.Lock()
	deadline := c.timeWriteDeadline
	c.deadlines.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, deadlineError{}
	}
	// Eight bytes of host headroom keep Geneve peer-relay encapsulation valid.
	// Buffers are pooled; the host borrows them until Send returns.
	packet := packetPool.Get().(*packetBuffer)
	size := len(buf) + 8
	if size > len(packet.small) {
		releasePacket(packet)
		return 0, errors.New("oversized outer QUIC packet")
	}
	packet.data = packet.small[:size]
	copy(packet.data[8:], buf)
	err := c.g.b.host.Bind.Send([][]byte{packet.data}, a.ep, 8)
	releasePacket(packet)
	if err != nil {
		return 0, err
	}
	c.g.b.counters.RawBytesSent.Add(uint64(len(buf)))
	return len(buf), nil
}

type deadlineError struct{}

func (deadlineError) Error() string   { return "i/o timeout" }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Temporary() bool { return true }

func (g *generation) readHost(fn conn.ReceiveFunc) {
	defer g.workers.Done()
	count := g.b.host.Bind.BatchSize()
	bufs := make([][]byte, count)
	sizes := make([]int, count)
	eps := make([]conn.Endpoint, count)
	var geometry []int
	if host, ok := g.b.host.Bind.(interface{ ReceiveBufferSizes() []int }); ok {
		geometry = host.ReceiveBufferSizes()
	}
	for i := range bufs {
		// Host Bind receives may read a coalesced UDP GRO datagram before
		// splitting. A QUIC-sized buffer here silently truncates that datagram.
		size := 65535
		if len(geometry) == count && geometry[i] >= 2048 && geometry[i] <= size {
			size = geometry[i]
		}
		bufs[i] = make([]byte, size)
	}
	for {
		n, err := fn(bufs, sizes, eps)
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || sizes[i] > len(bufs[i]) || eps[i] == nil {
				continue
			}
			data := bufs[i][:sizes[i]]
			// Only QUIC uses this data plane. Existing discovery was consumed by the
			// host already. Never forward unknown or plain WG packets to WG in strict
			// mode, even if a stale/legacy peer sends them to the native socket.
			if g.bridge == nil || len(data) < 21 || data[0]&0x40 == 0 {
				g.b.counters.RawPacketsDropped.Add(1)
				continue
			}
			packet := acquirePacket(data)
			select {
			case g.bridge.rx <- rawPacket{packet, &bindAddr{ep: eps[i]}}:
				g.b.counters.RawBytesReceived.Add(uint64(len(data)))
			case <-g.ctx.Done():
				releasePacket(packet)
				return
			default:
				releasePacket(packet)
				g.b.counters.ReceiveQueueDrops.Add(1)
			}
		}
		if g.ctx.Err() != nil {
			return
		}
	}
}

var _ net.PacketConn = (*bindPacketConn)(nil)
