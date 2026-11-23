// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"testing"
	"time"
)

// TestConnBindCloseFullDERPQueue checks that closing the bind does not
// block when a DERP read result is already queued and nothing is left to
// receive it, as after a packet device's receive workers have exited.
func TestConnBindCloseFullDERPQueue(t *testing.T) {
	c := &Conn{derpRecvCh: make(chan derpReadResult, 1)}
	c.derpRecvCh <- derpReadResult{} // pending result with no reader
	b := &connBind{Conn: c}
	done := make(chan struct{})
	go func() {
		b.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connBind.Close blocked on a full DERP receive queue")
	}
	if !b.isClosed() {
		t.Fatal("connBind not closed")
	}
	// A second Close is a no-op.
	if err := b.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

// TestConnBindCloseWakesDERPReceiver checks that Close still wakes a
// receiveDERP blocked on an empty queue.
func TestConnBindCloseWakesDERPReceiver(t *testing.T) {
	c := &Conn{derpRecvCh: make(chan derpReadResult, 1)}
	b := &connBind{Conn: c}
	got := make(chan derpReadResult, 1)
	go func() { got <- <-c.derpRecvCh }()
	b.Close()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not wake a blocked DERP receiver")
	}
}
