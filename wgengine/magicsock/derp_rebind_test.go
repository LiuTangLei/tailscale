// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"runtime"
	"testing"

	"tailscale.com/hostinfo"
)

func TestForcedDERPDoesNotRebindDisabledUDP(t *testing.T) {
	if runtime.GOOS == "js" || hostinfo.IsInVM86() {
		t.Skip("no UDP rebind on this target")
	}
	c := newTestConn(t)
	c.noV4Send.Store(true)
	// Test the policy directly instead of mutating a cached environment knob
	// while the connection's workers are already running.
	if !c.shouldRebindAfterSendErrorForPolicy(false) {
		t.Fatal("normal send failure stopped triggering rebind")
	}
	if c.shouldRebindAfterSendErrorForPolicy(true) {
		t.Fatal("forced DERP would tear down its relay to repair deliberately disabled UDP")
	}
	c.onlyTCP443.Store(true)
	if c.shouldRebindAfterSendErrorForPolicy(false) {
		t.Fatal("TCP-only mode rebound UDP")
	}
}
