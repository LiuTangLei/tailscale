// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import "sync"

const tcpWriteChunkSize = 32 << 10

type tcpWriteBuffer struct {
	data [tcpWriteChunkSize]byte
	n    int
}

var tcpWriteBuffers = sync.Pool{New: func() any { return new(tcpWriteBuffer) }}

// Copying preserves net.Conn.Write ownership: callers may immediately reuse
// accepted bytes. Only the owned storage is reused, after the framing writer
// finishes with it. Queue capacity and deadline/FIN behavior stay unchanged.
func copyTCPWriteBuffer(data []byte) *tcpWriteBuffer {
	if len(data) > tcpWriteChunkSize {
		panic("TCP write chunk exceeds internal bound")
	}
	b := tcpWriteBuffers.Get().(*tcpWriteBuffer)
	b.n = copy(b.data[:], data)
	return b
}

func releaseTCPWriteBuffer(b *tcpWriteBuffer) {
	if b == nil {
		return
	}
	b.n = 0
	tcpWriteBuffers.Put(b)
}
