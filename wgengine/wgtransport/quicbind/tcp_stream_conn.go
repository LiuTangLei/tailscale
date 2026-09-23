package quicbind

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type tcpReadResult struct {
	buffer *tcpReadBuffer
	err    error
}

// Framing is owned by two bounded pumps. Application deadlines must NOT
// interrupt an HTTP/3 DATA-frame header or partial frame write: retrying the
// net.Conn after such an interruption would otherwise corrupt the framing.
// Queues own their byte slices, just as kernel TCP owns successfully written
// bytes after Write returns. CloseWrite drains accepted bytes before FIN.
type tcpStreamConn struct {
	stream                                      reliableStream
	p                                           *peer
	s                                           *session
	local, remote                               net.Addr
	readMu, writeMu                             sync.Mutex
	mu                                          sync.Mutex
	readDeadline, writeDeadline                 time.Time
	readClosed, writeClosed                     bool
	writeErr                                    error
	wake                                        chan struct{}
	readQ                                       chan tcpReadResult
	writeQ                                      chan *tcpWriteBuffer
	readStop, writeStop, readerDone, writerDone chan struct{}
	closeOnce                                   sync.Once
	closeSignal                                 chan struct{}
	drained                                     chan struct{}
	drainErr                                    error          // published by closing drained
	current                                     *tcpReadBuffer // guarded by readMu
	readOffset                                  int            // guarded by readMu
	readErr                                     error          // guarded by readMu
}

func (b *Backend) newTCPConn(p *peer, s *session, stream reliableStream, local, remote net.Addr) *tcpStreamConn {
	c := &tcpStreamConn{stream: stream, p: p, s: s, local: local, remote: remote,
		wake: make(chan struct{}), readQ: make(chan tcpReadResult, 2), writeQ: make(chan *tcpWriteBuffer, 2),
		readStop: make(chan struct{}), writeStop: make(chan struct{}), readerDone: make(chan struct{}), writerDone: make(chan struct{}),
		closeSignal: make(chan struct{}), drained: make(chan struct{})}
	s.tcpActive.Add(1)
	b.tcpStreams.Store(c, struct{}{})
	b.counters.TCPStreams.Add(1)
	p.touch()
	go c.readPump()
	go c.writePump()
	go func() {
		select {
		case <-c.closeSignal:
		case <-s.q.Context().Done():
			_ = c.Close()
		}
		<-c.writerDone
		c.drainErr = stream.WaitWriteAcknowledged(s.q.Context())
		close(c.drained)
		b.tcpStreams.Delete(c)
		s.tcpActive.Add(-1)
	}()
	return c
}

// Done reports full connection closure, including shutdown of its QUIC session.
// Adapters handing a connection to net.Listener.Accept can retain the callback
// lifetime until its new owner closes it, without polling or leaking a waiter.
func (c *tcpStreamConn) Done() <-chan struct{} { return c.closeSignal }

func (c *tcpStreamConn) authorized() bool { return c.p.stampValid(c.s.stamp) }
func (c *tcpStreamConn) changedLocked()   { close(c.wake); c.wake = make(chan struct{}) }

func (c *tcpStreamConn) readPump() {
	defer func() {
		close(c.readQ)
		// Publish completion atomically with the close-state check. Either
		// this pump or closeRead must reclaim queued/current storage even
		// when EOF and Close race. releaseReadBuffers is idempotent.
		c.mu.Lock()
		closed := c.readClosed
		close(c.readerDone)
		c.mu.Unlock()
		if closed {
			c.releaseReadBuffers()
		}
	}()
	// CancelRead is a no-op after QUIC EOF. On a close-drain deadline or
	// malformed frame it releases the receive side instead of retaining it.
	defer c.stream.CancelRead(0)
	pool := &c.p.g.b.readBuffers
	for {
		block := pool.get()
		n, err := c.stream.Read(block.data[:])
		if n < 0 || n > len(block.data) {
			block.n = len(block.data)
			pool.put(block)
			block, n, err = nil, 0, io.ErrShortBuffer
		} else {
			block.n = n
		}
		if n > 0 {
			c.p.touch()
			c.p.g.b.counters.TCPBytesReceived.Add(uint64(n))
		} else if block != nil {
			pool.put(block)
			block = nil
		}
		if n > 0 || err != nil {
			select {
			case c.readQ <- tcpReadResult{block, err}:
				// Ownership passes to the queue and then the application Read.
			case <-c.readStop:
				if err == nil {
					if block == nil {
						block = pool.get()
					}
					c.drainClosedRead(block.data[:])
					block.n = len(block.data)
				}
				pool.put(block)
				return
			case <-c.p.ctx.Done():
				pool.put(block)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *tcpStreamConn) writeBuffer(buf *tcpWriteBuffer) bool {
	defer releaseTCPWriteBuffer(buf)
	if !c.authorized() {
		c.failWrite(net.ErrClosed)
		return false
	}
	n, err := c.stream.Write(buf.data[:buf.n])
	if n > 0 {
		c.p.touch()
		c.p.g.b.counters.TCPBytesSent.Add(uint64(n))
	}
	if err == nil && n != buf.n {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.failWrite(err)
		return false
	}
	return true
}
func (c *tcpStreamConn) failWrite(err error) {
	c.mu.Lock()
	c.writeErr = err
	c.changedLocked()
	c.mu.Unlock()
	c.stream.CancelWrite(1)
	_ = c.Close()
}
func (c *tcpStreamConn) notifyWriteSpace() { c.mu.Lock(); c.changedLocked(); c.mu.Unlock() }
func (c *tcpStreamConn) writePump() {
	defer close(c.writerDone)
	// On failure, failWrite closes admission before this drain. No accepted
	// buffer is leaked, reused early or left behind on revocation/shutdown.
	defer func() {
		for {
			select {
			case buf := <-c.writeQ:
				releaseTCPWriteBuffer(buf)
			default:
				return
			}
		}
	}()
	for {
		select {
		case buf := <-c.writeQ:
			c.notifyWriteSpace()
			if !c.writeBuffer(buf) {
				return
			}
		case <-c.writeStop:
			for {
				select {
				case buf := <-c.writeQ:
					if !c.writeBuffer(buf) {
						return
					}
				default:
					// A peer that already canceled an unused receiving half may
					// reject FIN; Close itself remains idempotent and non-failing.
					_ = c.stream.Close()
					return
				}
			}
		}
	}
}

func deadlineTimer(deadline time.Time) (<-chan time.Time, func()) {
	if deadline.IsZero() {
		return nil, func() {}
	}
	t := time.NewTimer(max(time.Duration(0), time.Until(deadline)))
	return t.C, func() { t.Stop() }
}

func (c *tcpStreamConn) Read(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	total := 0
	for {
		if !c.authorized() {
			return total, net.ErrClosed
		}
		c.mu.Lock()
		closed, deadline, wake := c.readClosed, c.readDeadline, c.wake
		c.mu.Unlock()
		if closed {
			return total, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return total, os.ErrDeadlineExceeded
		}
		if total == len(buf) {
			return total, nil
		}
		if c.current != nil {
			n := copy(buf[total:], c.current.data[c.readOffset:c.current.n])
			c.readOffset += n
			total += n
			if c.readOffset == c.current.n {
				c.releaseCurrentReadBuffer()
			}
			if total == len(buf) {
				return total, nil
			}
		}
		if c.readErr != nil {
			if total > 0 {
				return total, nil // deliver trailing data before its terminal error
			}
			return 0, c.readErr
		}
		if total > 0 {
			// Coalesce only already-ready chunks. Never wait for a larger
			// batch after obtaining bytes, preserving interactive latency.
			select {
			case result, ok := <-c.readQ:
				c.acceptReadResult(result, ok)
				continue
			default:
				return total, nil
			}
		}
		timer, stop := deadlineTimer(deadline)
		select {
		case result, ok := <-c.readQ:
			c.acceptReadResult(result, ok)
		case <-timer:
		case <-wake:
		case <-c.readStop:
		}
		stop()
	}
}

// All three helpers below serialize application ownership with readMu.
func (c *tcpStreamConn) acceptReadResult(result tcpReadResult, ok bool) {
	if !ok {
		c.readErr = io.EOF
		return
	}
	c.current, c.readErr, c.readOffset = result.buffer, result.err, 0
}

func (c *tcpStreamConn) releaseCurrentReadBuffer() {
	if c.current != nil {
		c.p.g.b.readBuffers.put(c.current)
		c.current, c.readOffset = nil, 0
	}
}

// Called only after readQ is closed; never race a final enqueue.
func (c *tcpStreamConn) releaseReadBuffers() {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.releaseCurrentReadBuffer()
	for result := range c.readQ {
		c.p.g.b.readBuffers.put(result.buffer)
	}
}
func (c *tcpStreamConn) Write(buf []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	accepted := 0
	for {
		if !c.authorized() {
			return accepted, net.ErrClosed
		}
		c.mu.Lock()
		if c.writeErr != nil {
			err := c.writeErr
			c.mu.Unlock()
			return accepted, err
		}
		if c.writeClosed {
			c.mu.Unlock()
			return accepted, net.ErrClosed
		}
		deadline, wake := c.writeDeadline, c.wake
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			c.mu.Unlock()
			return accepted, os.ErrDeadlineExceeded
		}
		if len(buf) == 0 {
			c.mu.Unlock()
			return accepted, nil
		}
		n := min(len(buf), 32<<10)
		// The lock makes acceptance atomic with CloseWrite. No bytes can be
		// queued after the writer begins draining a closed queue.
		if len(c.writeQ) < cap(c.writeQ) {
			c.writeQ <- copyTCPWriteBuffer(buf[:n])
			c.mu.Unlock()
			accepted += n
			buf = buf[n:]
			continue
		}
		c.mu.Unlock()
		timer, stop := deadlineTimer(deadline)
		select {
		case <-wake:
		case <-timer:
		case <-c.writeStop:
		}
		stop()
	}
}
func (c *tcpStreamConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.writeClosed {
		c.writeClosed = true
		close(c.writeStop)
		c.changedLocked()
	}
	return nil
}

const (
	// Normal connection Close must not race STOP_SENDING against a peer's
	// final SSH disconnect/FIN. Bound post-close receive work independently
	// of the sender's acknowledged-write drain. Explicit CloseRead still
	// aborts immediately; neither path reports a reset as successful delivery.
	closedReadGrace = 5 * time.Second
	closedReadLimit = 1 << 20
)

func (c *tcpStreamConn) closeRead(graceful bool) {
	c.mu.Lock()
	if !c.readClosed {
		if graceful {
			// Application read deadlines are only wrapper-level; after full
			// Close this underlying deadline bounds the existing read pump.
			_ = c.stream.SetReadDeadline(time.Now().Add(closedReadGrace))
		}
		c.readClosed = true
		close(c.readStop)
		c.changedLocked()
	}
	c.mu.Unlock()
	if !graceful {
		c.stream.CancelRead(0)
		if c.readerDone != nil {
			<-c.readerDone
		}
	}
	select {
	case <-c.readerDone:
		c.releaseReadBuffers()
	default:
		// A graceful Close stays nonblocking. The existing pump reclaims
		// storage when its bounded EOF/close drain completes; no new worker.
	}
}

// drainClosedRead discards only data addressed to this already authenticated,
// locally closed connection. This permits the peer's final bytes and FIN to
// reach QUIC acknowledgement, without keeping an application Read alive or
// allocating another goroutine. An uncooperative peer is cut off by both the
// byte budget and closeRead's absolute deadline; revocation remains immediate.
func (c *tcpStreamConn) drainClosedRead(buf []byte) {
	for remaining := closedReadLimit; remaining > 0 && c.authorized(); {
		n, err := c.stream.Read(buf[:min(len(buf), remaining)])
		remaining -= n
		if err == io.EOF {
			return
		}
		if err != nil || n == 0 {
			break
		}
	}
	c.stream.CancelRead(0)
}

func (c *tcpStreamConn) CloseRead() error {
	c.closeRead(false)
	return nil
}
func (c *tcpStreamConn) Close() error {
	c.closeOnce.Do(func() { _ = c.CloseWrite(); c.closeRead(true); close(c.closeSignal) })
	return nil
}
func (c *tcpStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *tcpStreamConn) RemoteAddr() net.Addr { return c.remote }
func (c *tcpStreamConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline, c.writeDeadline = t, t
	c.changedLocked()
	return nil
}
func (c *tcpStreamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.changedLocked()
	return nil
}
func (c *tcpStreamConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	c.changedLocked()
	return nil
}
