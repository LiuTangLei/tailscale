// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"runtime"
	"testing"
)

func TestCarrierReceiveBufferGeometry(t *testing.T) {
	b := &connBind{}
	sizes := b.ReceiveBufferSizes()
	if len(sizes) != b.BatchSize() {
		t.Fatal("geometry differs from batch size")
	}
	for i, n := range sizes {
		want := 2048
		if runtime.GOOS == "linux" && i >= len(sizes)-2 {
			want = 65535
		}
		if n != want {
			t.Fatalf("slot %d size %d, want %d", i, n, want)
		}
	}
}
