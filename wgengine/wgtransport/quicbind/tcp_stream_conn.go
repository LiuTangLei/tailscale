package quicbind

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type tcpReadResult struct { data []byte; err error }

// Framing is owned by two bounded pumps. Application deadlines must NOT
// interrupt an HTTP/3 DATA-frame header or partial frame write: retrying the
// net.Conn after such an interruption would otherwise corrupt the framing.
// Queues own their byte slices, just as kernel TCP owns successfully written
// bytes after Write returns. CloseWrite drains accepted bytes before FIN.
type tcpStreamConn struct {
	stream reliableStream
	p *peer
	s *session
	local, remote net.Addr
	readMu, writeMu sync.Mutex
	mu sync.Mutex
	readDeadline, writeDeadline time.Time
	readClosed, writeClosed bool
	writeErr error
	wake chan struct{}
	readQ chan tcpReadResult
	writeQ chan []byte
	readStop, writeStop, readerDone, writerDone chan struct{}
	closeOnce sync.Once
	closeSignal chan struct{}
	drained chan struct{}
	drainErr error // published by closing drained
	current []byte // guarded by readMu
	readErr error  // guarded by readMu
}

func (b *Backend) newTCPConn(p *peer, s *session, stream reliableStream, local, remote net.Addr) *tcpStreamConn {
	c:=&tcpStreamConn{stream:stream,p:p,s:s,local:local,remote:remote,
		wake:make(chan struct{}), readQ:make(chan tcpReadResult,2),writeQ:make(chan []byte,2),
		readStop:make(chan struct{}),writeStop:make(chan struct{}),readerDone:make(chan struct{}),writerDone:make(chan struct{}),
		closeSignal:make(chan struct{}),drained:make(chan struct{})}
	s.tcpActive.Add(1)
	b.tcpStreams.Store(c,struct{}{})
	b.counters.TCPStreams.Add(1)
	p.touch()
	go c.readPump()
	go c.writePump()
	go func(){
		select {
		case <-c.closeSignal:
		case <-s.q.Context().Done(): _ = c.Close()
		}
		<-c.writerDone
		c.drainErr=stream.WaitWriteAcknowledged(s.q.Context())
		close(c.drained)
		b.tcpStreams.Delete(c)
		s.tcpActive.Add(-1)
	}()
	return c
}

func (c *tcpStreamConn) authorized() bool { return c.p.stampValid(c.s.stamp) }
func (c *tcpStreamConn) changedLocked() { close(c.wake);c.wake=make(chan struct{}) }

func (c *tcpStreamConn) readPump() {
	defer close(c.readerDone)
	defer close(c.readQ)
	for {
		buf:=make([]byte,32<<10)
		n,err:=c.stream.Read(buf)
		if n>0 {
			c.p.touch()
			c.p.g.b.counters.TCPBytesReceived.Add(uint64(n))
		}
		if n>0 || err!=nil {
			select {
			case c.readQ<-tcpReadResult{buf[:n],err}:
			case <-c.readStop:return
			case <-c.p.ctx.Done():return
			}
		}
		if err!=nil {return}
	}
}

func (c *tcpStreamConn) writeBuffer(buf []byte) bool {
	if !c.authorized() { c.failWrite(net.ErrClosed);return false }
	n,err:=c.stream.Write(buf)
	if n>0 {c.p.touch();c.p.g.b.counters.TCPBytesSent.Add(uint64(n))}
	if err==nil && n!=len(buf) {err=io.ErrShortWrite}
	if err!=nil {c.failWrite(err);return false}
	return true
}
func (c *tcpStreamConn) failWrite(err error) {
	c.mu.Lock();c.writeErr=err;c.changedLocked();c.mu.Unlock()
	c.stream.CancelWrite(1)
	_ = c.Close()
}
func (c *tcpStreamConn) notifyWriteSpace() {c.mu.Lock();c.changedLocked();c.mu.Unlock()}
func (c *tcpStreamConn) writePump() {
	defer close(c.writerDone)
	for {
		select {
		case buf:=<-c.writeQ:
			c.notifyWriteSpace()
			if !c.writeBuffer(buf) {return}
		case <-c.writeStop:
			for {
				select {
				case buf:=<-c.writeQ:
					if !c.writeBuffer(buf) {return}
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

func deadlineTimer(deadline time.Time) (<-chan time.Time,func()) {
	if deadline.IsZero() {return nil,func(){}}
	t:=time.NewTimer(max(time.Duration(0),time.Until(deadline)))
	return t.C,func(){t.Stop()}
}

func (c *tcpStreamConn) Read(buf []byte) (int,error) {
	c.readMu.Lock();defer c.readMu.Unlock()
	for {
		if !c.authorized() {return 0,net.ErrClosed}
		c.mu.Lock()
		closed,deadline,wake:=c.readClosed,c.readDeadline,c.wake
		c.mu.Unlock()
		if closed {return 0,net.ErrClosed}
		if !deadline.IsZero() && !time.Now().Before(deadline) {return 0,os.ErrDeadlineExceeded}
		if len(buf)==0 {return 0,nil}
		if len(c.current)>0 {
			n:=copy(buf,c.current);c.current=c.current[n:]
			return n,nil
		}
		if c.readErr!=nil {return 0,c.readErr}
		timer,stop:=deadlineTimer(deadline)
		select {
		case result,ok:=<-c.readQ:
			if !ok {c.readErr=io.EOF} else {c.current,c.readErr=result.data,result.err}
		case <-timer:
		case <-wake:
		case <-c.readStop:
		}
		stop()
	}
}
func (c *tcpStreamConn) Write(buf []byte) (int,error) {
	c.writeMu.Lock();defer c.writeMu.Unlock()
	accepted:=0
	for {
		if !c.authorized() {return accepted,net.ErrClosed}
		c.mu.Lock()
		if c.writeErr!=nil {err:=c.writeErr;c.mu.Unlock();return accepted,err}
		if c.writeClosed {c.mu.Unlock();return accepted,net.ErrClosed}
		deadline,wake:=c.writeDeadline,c.wake
		if !deadline.IsZero() && !time.Now().Before(deadline) {c.mu.Unlock();return accepted,os.ErrDeadlineExceeded}
		if len(buf)==0 {c.mu.Unlock();return accepted,nil}
		n:=min(len(buf),32<<10)
		// The lock makes acceptance atomic with CloseWrite. No bytes can be
		// queued after the writer begins draining a closed queue.
		if len(c.writeQ)<cap(c.writeQ) {
			c.writeQ<-bytes.Clone(buf[:n]);c.mu.Unlock()
			accepted+=n;buf=buf[n:]
			continue
		}
		c.mu.Unlock()
		timer,stop:=deadlineTimer(deadline)
		select {case <-wake:case <-timer:case <-c.writeStop:}
		stop()
	}
}
func (c *tcpStreamConn) CloseWrite() error {
	c.mu.Lock();defer c.mu.Unlock()
	if !c.writeClosed {c.writeClosed=true;close(c.writeStop);c.changedLocked()}
	return nil
}
func (c *tcpStreamConn) CloseRead() error {
	c.mu.Lock()
	if !c.readClosed {c.readClosed=true;close(c.readStop);c.changedLocked()}
	c.mu.Unlock()
	c.stream.CancelRead(0)
	return nil
}
func (c *tcpStreamConn) Close() error {
	c.closeOnce.Do(func(){_ = c.CloseWrite();_ = c.CloseRead();close(c.closeSignal)})
	return nil
}
func (c *tcpStreamConn) LocalAddr() net.Addr{return c.local}
func (c *tcpStreamConn) RemoteAddr() net.Addr{return c.remote}
func (c *tcpStreamConn) SetDeadline(t time.Time) error {
	c.mu.Lock();defer c.mu.Unlock()
	c.readDeadline,c.writeDeadline=t,t;c.changedLocked();return nil
}
func (c *tcpStreamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock();defer c.mu.Unlock()
	c.readDeadline=t;c.changedLocked();return nil
}
func (c *tcpStreamConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock();defer c.mu.Unlock()
	c.writeDeadline=t;c.changedLocked();return nil
}
