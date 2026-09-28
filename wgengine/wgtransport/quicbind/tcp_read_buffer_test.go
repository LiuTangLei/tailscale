// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"tailscale.com/wgengine/wgtransport"
)

type pooledReadTestStream struct {
	failingTCPWriter
	read   func([]byte) (int, error)
	cancel func()
}

func (s *pooledReadTestStream) Read(b []byte) (int, error) { return s.read(b) }
func (s *pooledReadTestStream) CancelRead(quic.StreamErrorCode) {
	if s.cancel != nil {
		s.cancel()
	}
}

func newPooledReadFixture(t *testing.T, stream reliableStream) (*tcpStreamConn, *Backend) {
	t.Helper()
	b := &Backend{host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
	b.identityOK.Store(true)
	p := &peer{ctx: context.Background(), g: &generation{b: b}, cfg: peerConfig{key: [32]byte{1}}}
	c := &tcpStreamConn{p: p, s: &session{stamp: p.lifecycleStamp()}, stream: stream,
		readQ: make(chan tcpReadResult, 2), readStop: make(chan struct{}),
		readerDone: make(chan struct{}), wake: make(chan struct{})}
	if stream != nil {
		go c.readPump()
		t.Cleanup(func() { c.CloseRead() })
	}
	return c, b
}

func assertReadPoolEmpty(t *testing.T, b *Backend) {
	t.Helper()
	s := b.readBuffers.snapshot()
	if s["in_use"] != 0 || s["gets"] != s["puts"] {
		t.Fatalf("read buffer leak or duplicate return: %+v", s)
	}
}

func TestTCPReadPoolBoundAndClear(t *testing.T) {
	var p tcpReadBufferPool
	blocks := make([]*tcpReadBuffer, maxIdleTCPReadBuffers+8)
	for i := range blocks {
		blocks[i] = p.get()
		blocks[i].n = copy(blocks[i].data[:], bytes.Repeat([]byte{0xc5}, tcpReadChunkSize))
	}
	for _, b := range blocks {
		p.put(b)
	}
	s := p.snapshot()
	if s["idle"] != maxIdleTCPReadBuffers || s["discarded"] != 8 || s["in_use"] != 0 {
		t.Fatalf("pool not bounded: %+v", s)
	}
	for i := 0; i < maxIdleTCPReadBuffers; i++ {
		b := p.get()
		if b.n != 0 || !bytes.Equal(b.data[:], make([]byte, tcpReadChunkSize)) {
			t.Fatal("previous stream bytes retained")
		}
		blocks[i] = b
	}
	for _, b := range blocks[:maxIdleTCPReadBuffers] {
		p.put(b)
	}
}

func TestTCPReadPoolDeadlinePreservesPartial(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	c, b := newPooledReadFixture(t, &pooledReadTestStream{read: r.Read, cancel: func() { r.Close() }})
	payload := bytes.Repeat([]byte("owned-read-payload"), 100)
	written := make(chan error, 1)
	go func() { _, err := w.Write(payload); written <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got[:7]); err != nil {
		t.Fatal(err)
	}
	owned := c.current
	if owned == nil || c.readOffset != 7 {
		t.Fatal("partial block not retained")
	}
	c.SetReadDeadline(time.Now().Add(-time.Second))
	if n, err := c.Read(got[7:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline: %d %v", n, err)
	}
	if c.current != owned || c.readOffset != 7 {
		t.Fatal("deadline recycled unread storage")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, got[7:]); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("partial contents: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	c.CloseRead()
	assertReadPoolEmpty(t, b)
}

func TestTCPReadyReadCoalescesWithoutWaiting(t *testing.T) {
	c, b := newPooledReadFixture(t, nil)
	for _, text := range []string{"first", "second"} {
		block := b.readBuffers.get()
		block.n = copy(block.data[:], text)
		c.readQ <- tcpReadResult{buffer: block}
	}
	done := make(chan struct{})
	var n int
	var err error
	buf := make([]byte, 100)
	go func() { n, err = c.Read(buf); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Read waited to fill unused application buffer")
	}
	if err != nil || string(buf[:n]) != "firstsecond" {
		t.Fatalf("ready chunks not coalesced: %q %v", buf[:n], err)
	}
	assertReadPoolEmpty(t, b)
}

func TestTCPReadPoolDataWithEOF(t *testing.T) {
	want := bytes.Repeat([]byte("final-data"), 19)
	c, b := newPooledReadFixture(t, &pooledReadTestStream{read: func(p []byte) (int, error) { return copy(p, want), io.EOF }})
	<-c.readerDone
	if s := b.readBuffers.snapshot(); s["in_use"] != 1 {
		t.Fatalf("EOF data lost ownership: %+v", s)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("EOF contents: %v", err)
	}
	assertReadPoolEmpty(t, b)
}

func TestTCPReadPoolConcurrentCloseFullQueue(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	c, b := newPooledReadFixture(t, &pooledReadTestStream{read: r.Read, cancel: func() { r.Close() }})
	done := make(chan struct{})
	go func() { defer close(done); w.Write(make([]byte, 5*tcpReadChunkSize)) }()
	deadline := time.Now().Add(time.Second)
	for len(c.readQ) != cap(c.readQ) {
		if time.Now().After(deadline) {
			t.Fatal("fixture queue did not fill")
		}
		time.Sleep(time.Millisecond)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.CloseRead() }()
	}
	wg.Wait()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close left stream reader blocked")
	}
	assertReadPoolEmpty(t, b)
}

func TestTCPReadPoolGracefulCloseEOFRace(t *testing.T) {
	for i := 0; i < 100; i++ {
		ready := make(chan struct{})
		c, b := newPooledReadFixture(t, &pooledReadTestStream{read: func(p []byte) (int, error) {
			<-ready
			return copy(p, "unread final bytes"), io.EOF
		}})
		go close(ready)
		c.closeRead(true)
		<-c.readerDone
		// CloseRead joins reclamation even if the graceful pump's deferred
		// cleanup was racing completion. It must never return a block twice.
		c.CloseRead()
		assertReadPoolEmpty(t, b)
	}
}

var benchmarkReadBuffer any

func BenchmarkTCPReadBuffer(b *testing.B) {
	b.Run("allocate-32KiB", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(tcpReadChunkSize)
		for i := 0; i < b.N; i++ {
			buf := make([]byte, tcpReadChunkSize)
			buf[0] = byte(i)
			benchmarkReadBuffer = buf
		}
	})
	b.Run("pool-32KiB-clear", func(b *testing.B) {
		var p tcpReadBufferPool
		buf := p.get()
		p.put(buf)
		b.ReportAllocs()
		b.SetBytes(tcpReadChunkSize)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buf := p.get()
			buf.n = tcpReadChunkSize
			buf.data[0] = byte(i)
			benchmarkReadBuffer = buf
			p.put(buf)
		}
	})
}
