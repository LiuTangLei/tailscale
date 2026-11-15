package quicbind

import (
	"sync/atomic"
	"time"
)

// Stream counters distinguish application admission backpressure from time in
// the reliable HTTP/3 writer. They retain no stream, peer or packet storage.
type tcpStreamMetrics struct {
	queueWaits, queueWaitNS, queueWaitMaxNS      atomic.Uint64
	waitingWriters                               atomic.Int64
	writeCalls, writeNS, writeMaxNS, writeErrors atomic.Uint64
	finWaits, finWaitNS, finWaitErrors           atomic.Uint64
	aborts, discardedReadBytes                   atomic.Uint64
}

func recordTCPDuration(total, maximum *atomic.Uint64, elapsed time.Duration) {
	ns := uint64(elapsed)
	total.Add(ns)
	for old := maximum.Load(); ns > old; old = maximum.Load() {
		if maximum.CompareAndSwap(old, ns) {
			break
		}
	}
}

func (m *tcpStreamMetrics) snapshot() map[string]any {
	return map[string]any{
		"queue_waits": m.queueWaits.Load(), "queue_wait_ns": m.queueWaitNS.Load(),
		"queue_wait_max_ns": m.queueWaitMaxNS.Load(), "waiting_writers": m.waitingWriters.Load(),
		"stream_write_calls": m.writeCalls.Load(), "stream_write_ns": m.writeNS.Load(),
		"stream_write_max_ns": m.writeMaxNS.Load(), "stream_write_errors": m.writeErrors.Load(),
		"fin_waits": m.finWaits.Load(), "fin_wait_ns": m.finWaitNS.Load(), "fin_wait_errors": m.finWaitErrors.Load(),
		"aborted_streams": m.aborts.Load(), "discarded_after_close_bytes": m.discardedReadBytes.Load(),
	}
}
