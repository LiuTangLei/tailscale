package quicbind

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTP3AbortStopsQueuedStreamImmediately(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	c, accepted := newCloseDrainPair(t, func(conn net.Conn) {
		defer conn.Close()
		if calls.Add(1) == 1 {
			<-release // application deliberately stops reading this stream
			return
		}
		_, _ = io.Copy(conn, conn)
	})
	<-accepted
	t.Cleanup(func() {
		close(release)
		_ = c.s.q.CloseWithError(0, "abort test cleanup")
	})
	written := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 16<<20)); written <- err }()
	deadline := time.Now().Add(3 * time.Second)
	for len(c.writeQ) != cap(c.writeQ) || c.p.g.b.tcpStreamMetrics.waitingWriters.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("test never filled write queue")
		}
		time.Sleep(time.Millisecond)
	}
	// Model the old proxy's full Close fallback, then require the explicit
	// abort operation to release pumps without the normal FIN/read grace.
	start := time.Now()
	if aborter, ok := any(c).(interface{ Abort() error }); ok {
		_ = aborter.Abort()
	} else {
		_ = c.Close()
	}
	for name, done := range map[string]<-chan struct{}{"reader": c.readerDone, "writer": c.writerDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("explicit abort retained %s pump", name)
		}
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("aborted write reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("application write did not wake")
	}
	_ = c.Abort() // explicit abort must be idempotent
	metrics := &c.p.g.b.tcpStreamMetrics
	if metrics.aborts.Load() != 1 || metrics.waitingWriters.Load() != 0 || metrics.queueWaits.Load() == 0 || metrics.queueWaitMaxNS.Load() == 0 {
		t.Fatalf("abort/backpressure counters inconsistent: %+v", metrics.snapshot())
	}
	if c.s.q.Context().Err() != nil {
		t.Fatal("aborting a stream closed its shared QUIC connection")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	key := c.p.cfg.key
	next, err := c.p.g.b.DialTCPStream(ctx, key, netip.AddrPortFrom(tcpTestAddress(key), 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.(*tcpStreamConn).s.q != c.s.q {
		t.Fatal("stream abort forced connection replacement")
	}
	_ = next.SetDeadline(time.Now().Add(2 * time.Second))
	payload := bytes.Repeat([]byte("same authenticated connection\x00"), 128)
	if _, err = next.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = next.(*tcpStreamConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(next)
	if err != nil || !bytes.Equal(payload, got) {
		t.Fatalf("next stream lost final bytes/FIN: %v", err)
	}
	t.Logf("aborted queued stream and reused original QUIC connection in %s", time.Since(start))
}
