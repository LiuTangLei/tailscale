// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"runtime"
	"tailscale.com/hostinfo"
	"testing"
)

func TestForcedDERPDoesNotRebindDisabledUDP(t *testing.T) {
	if runtime.GOOS == "js" || hostinfo.IsInVM86() {
		t.Skip("no UDP rebind on this target")
	}
	c := newTestConn(t)
	c.noV4Send.Store(true)
	t.Setenv("TS_DEBUG_ALWAYS_USE_DERP", "false")
	if !c.shouldRebindAfterNetcheckSendError() {
		t.Fatal("normal send failure stopped triggering rebind")
	}
	t.Setenv("TS_DEBUG_ALWAYS_USE_DERP", "true")
	if c.shouldRebindAfterNetcheckSendError() {
		t.Fatal("forced DERP would tear down its relay to repair deliberately disabled UDP")
	}
	t.Setenv("TS_DEBUG_ALWAYS_USE_DERP", "false")
	c.onlyTCP443.Store(true)
	if c.shouldRebindAfterNetcheckSendError() {
		t.Fatal("TCP-only mode rebound UDP")
	}
}
