// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import "sync"

const (
	tcpReadChunkSize      = 32 << 10
	maxIdleTCPReadBuffers = 64 // at most 2 MiB cached per backend
)

type tcpReadBuffer struct {
	data [tcpReadChunkSize]byte
	n    int
}

// Buffers move pump -> bounded read queue -> Read -> pool. Partial reads and
// application deadlines retain exclusive ownership until consumed or closed.
// Active buffers are bounded by the existing queue plus reader/pump slots.
// Unlike sync.Pool, idle retention has an explicit, GC-independent byte bound.
// This adapts the unshipped e533804d0 read-pool experiment to graceful close.
type tcpReadBufferPool struct {
	mu    sync.Mutex
	idle  [maxIdleTCPReadBuffers]*tcpReadBuffer
	count int

	gets, allocs, puts, discarded, inUse, peakInUse uint64
}

func (p *tcpReadBufferPool) get() *tcpReadBuffer {
	p.mu.Lock()
	p.gets++
	p.inUse++
	p.peakInUse = max(p.peakInUse, p.inUse)
	if p.count > 0 {
		p.count--
		b := p.idle[p.count]
		p.idle[p.count] = nil
		p.mu.Unlock()
		return b
	}
	p.allocs++
	p.mu.Unlock()
	return new(tcpReadBuffer)
}

func (p *tcpReadBufferPool) put(b *tcpReadBuffer) {
	if b == nil {
		return
	}
	// Clear before exposing storage to a different authenticated stream.
	clear(b.data[:b.n])
	b.n = 0
	p.mu.Lock()
	defer p.mu.Unlock()
	p.puts++
	p.inUse--
	if p.count == len(p.idle) {
		p.discarded++
		return
	}
	p.idle[p.count] = b
	p.count++
}

func (p *tcpReadBufferPool) snapshot() map[string]uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]uint64{
		"gets": p.gets, "allocations": p.allocs, "puts": p.puts,
		"discarded": p.discarded, "in_use": p.inUse, "peak_in_use": p.peakInUse,
		"idle": uint64(p.count), "max_idle": maxIdleTCPReadBuffers,
		"chunk_bytes": tcpReadChunkSize,
	}
}
