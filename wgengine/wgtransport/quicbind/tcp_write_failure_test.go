// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"tailscale.com/wgengine/wgtransport"
)

type failingTCPWriter struct{ writes int }

func (f *failingTCPWriter) Write([]byte) (int, error)                 { f.writes++; return 0, io.ErrClosedPipe }
func (*failingTCPWriter) Read([]byte) (int, error)                    { return 0, io.EOF }
func (*failingTCPWriter) Close() error                                { return nil }
func (*failingTCPWriter) CancelRead(quic.StreamErrorCode)             {}
func (*failingTCPWriter) CancelWrite(quic.StreamErrorCode)            {}
func (*failingTCPWriter) SetDeadline(time.Time) error                 { return nil }
func (*failingTCPWriter) SetReadDeadline(time.Time) error             { return nil }
func (*failingTCPWriter) SetWriteDeadline(time.Time) error            { return nil }
func (*failingTCPWriter) WaitWriteAcknowledged(context.Context) error { return io.ErrClosedPipe }

func TestTCPWritePumpFailureDrainsOwnedQueue(t *testing.T) {
	backend := &Backend{host: wgtransport.Host{PeerAllowed: func([32]byte) bool { return true }}}
	backend.identityOK.Store(true)
	p := &peer{g: &generation{b: backend}, cfg: peerConfig{key: [32]byte{1}}}
	s := &session{stamp: p.lifecycleStamp()}
	stream := &failingTCPWriter{}
	c := &tcpStreamConn{p: p, s: s, stream: stream, writeQ: make(chan *tcpWriteBuffer, 2),
		wake: make(chan struct{}), writeStop: make(chan struct{}), readStop: make(chan struct{}),
		writerDone: make(chan struct{}), closeSignal: make(chan struct{})}
	c.writeQ <- copyTCPWriteBuffer([]byte("first accepted buffer"))
	c.writeQ <- copyTCPWriteBuffer([]byte("second accepted buffer"))
	go c.writePump()
	select {
	case <-c.writerDone:
	case <-time.After(time.Second):
		t.Fatal("failed writer did not stop")
	}
	if len(c.writeQ) != 0 || stream.writes != 1 {
		t.Fatal("failed write leaked queue entries or retried data")
	}
	if _, err := c.Write([]byte("late write")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write admission remained open: %v", err)
	}
}
