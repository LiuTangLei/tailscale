// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"testing"
	"time"
)

// A carrier can stop its receive workers before closing the host Bind. If a
// DERP result is already queued, Close must not wait for a nonexistent reader
// while holding the same mutex that receiveDERP needs to observe closed.
func TestConnBindCloseWithQueuedDERP(t *testing.T) {
	for _, full := range []bool{false, true} {
		name := "empty"
		if full {
			name = "full"
		}
		t.Run(name, func(t *testing.T) {
			c := &Conn{derpRecvCh: make(chan derpReadResult, 1)}
			b := &connBind{Conn: c}
			if full {
				c.derpRecvCh <- derpReadResult{}
			}
			done := make(chan error, 1)
			go func() { done <- b.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				// Unstick the old implementation before reporting its failure;
				// the regression must not itself leak a blocked close goroutine.
				select {
				case <-c.derpRecvCh:
				default:
				}
				<-done
				t.Fatal("Bind.Close blocked on a full DERP receive queue")
			}
			if !b.isClosed() || len(c.derpRecvCh) != 1 {
				t.Fatal("close did not preserve a wakeup and the closed state")
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
