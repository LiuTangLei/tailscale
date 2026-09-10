// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"testing"
)

var tcpWriteBenchmarkSink []byte

func TestTCPWriteBufferOwnsAcceptedBytes(t *testing.T) {
	for _, size := range []int{0, 1, 1279, 32768, 7} {
		source := bytes.Repeat([]byte{byte(size + 1)}, size)
		want := bytes.Clone(source)
		b := copyTCPWriteBuffer(source)
		clear(source)
		if b.n != size || !bytes.Equal(b.data[:b.n], want) {
			t.Fatal("queued write borrowed caller storage or leaked stale bytes")
		}
		releaseTCPWriteBuffer(b)
	}
}

func BenchmarkTCPWriteQueueStorage(b *testing.B) {
	source := make([]byte, tcpWriteChunkSize)
	b.Run("previous-clone", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(source)))
		for b.Loop() {
			tcpWriteBenchmarkSink = bytes.Clone(source)
		}
	})
	b.Run("owned-pool", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(source)))
		for b.Loop() {
			owned := copyTCPWriteBuffer(source)
			if owned.n != len(source) {
				b.Fatal("short copy")
			}
			releaseTCPWriteBuffer(owned)
		}
	})
}
