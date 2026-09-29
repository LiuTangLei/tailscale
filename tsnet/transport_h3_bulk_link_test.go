// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/wgengine/wgtransport"
)

const (
	h3BulkLinkBytesPerSecond = 20_000_000 / 8
	h3BulkLinkDelay          = 30 * time.Millisecond
	h3BulkLinkQueueBytes     = 600_000 // four 20 Mbps * 60 ms bandwidth-delay products
)

// This test-only decorator sees exact outer QUIC packets, before magicsock
// chooses a physical path. No inner TCP or file writes are rate limited.
// It returns the original backend so lifecycle/authentication/diagnostics
// interfaces retain their normal implementations.
type h3BulkFactory struct {
	wgtransport.Factory
	shape          bool
	bytesPerSecond int64
	queueBytes     int
	backend        wgtransport.Backend
	link           *h3BulkShapedBind
}

func (f *h3BulkFactory) New(host wgtransport.Host) (wgtransport.Backend, error) {
	if f.shape {
		f.link = &h3BulkShapedBind{Bind: host.Bind, bytesPerSecond: f.bytesPerSecond, queueBytes: f.queueBytes}
		host.Bind = f.link
	}
	b, err := f.Factory.New(host)
	if err == nil {
		f.backend = b
	}
	return b, err
}

func (f *h3BulkFactory) reconnect() error {
	lifecycle, ok := f.backend.(wgtransport.NetworkLifecycle)
	if !ok {
		return errors.New("H3 benchmark backend lacks network lifecycle")
	}
	// Same isolated-backend operation as a host rebind. It closes current
	// sessions without forgetting authenticated remote server declarations.
	lifecycle.NetworkChanged(true, true)
	return nil
}

type h3BulkLinkStats struct {
	AcceptedPackets uint64 `json:"accepted_packets"`
	AcceptedBytes   uint64 `json:"accepted_quic_bytes"`
	DeliveredBytes  uint64 `json:"delivered_quic_bytes"`
	DroppedPackets  uint64 `json:"dropped_packets"`
	DroppedBytes    uint64 `json:"dropped_quic_bytes"`
	SendErrors      uint64 `json:"send_errors"`
	HostSendCalls   uint64 `json:"host_send_calls"`
	HostSendPackets uint64 `json:"host_send_packets"`
	QueuedBytes     int    `json:"queued_quic_bytes"`
	MaxQueuedBytes  int64  `json:"max_queued_quic_bytes"`
}

type h3BulkShapedBind struct {
	conn.Bind
	bytesPerSecond int64
	queueBytes     int
	mu             sync.Mutex // serializes Open/Close; Send only loads the current link
	current        *h3BulkLink

	acceptedPackets atomic.Uint64
	acceptedBytes   atomic.Uint64
	deliveredBytes  atomic.Uint64
	droppedPackets  atomic.Uint64
	droppedBytes    atomic.Uint64
	sendErrors      atomic.Uint64
	hostSendCalls   atomic.Uint64
	hostSendPackets atomic.Uint64
	maxQueuedBytes  atomic.Int64
}

func (b *h3BulkShapedBind) rate() int64 {
	if b.bytesPerSecond > 0 {
		return b.bytesPerSecond
	}
	return h3BulkLinkBytesPerSecond
}

func (b *h3BulkShapedBind) capacity() int {
	if b.queueBytes > 0 {
		return b.queueBytes
	}
	return h3BulkLinkQueueBytes
}

type h3BulkLinkPacket struct {
	data   []byte
	ep     conn.Endpoint
	offset int
	due    time.Time
}

type h3BulkLink struct {
	owner    *h3BulkShapedBind
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	wake     chan struct{}
	mu       sync.Mutex
	queue    []h3BulkLinkPacket
	head     int
	bytes    int
	nextSend time.Time
}

func (b *h3BulkShapedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	link := &h3BulkLink{owner: b, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	b.current = link
	go link.run()
	return fns, actual, nil
}

func (b *h3BulkShapedBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	link := b.current
	b.current = nil
	if link != nil {
		link.cancel()
	}
	// Unblock a real underlying Send before joining the scheduler.
	err := b.Bind.Close()
	if link != nil {
		<-link.done
	}
	return err
}

func (b *h3BulkShapedBind) ReceiveBufferSizes() []int {
	if geometry, ok := b.Bind.(interface{ ReceiveBufferSizes() []int }); ok {
		return geometry.ReceiveBufferSizes()
	}
	return nil
}

func (b *h3BulkShapedBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	link := b.current
	b.mu.Unlock()
	if link == nil {
		return net.ErrClosed
	}
	link.mu.Lock()
	defer link.mu.Unlock()
	if link.ctx.Err() != nil {
		return net.ErrClosed
	}
	for _, data := range bufs {
		if offset < 0 || offset >= len(data) {
			return errors.New("invalid shaped QUIC packet offset")
		}
		length := len(data) - offset
		if link.bytes+length > b.capacity() {
			b.droppedPackets.Add(1)
			b.droppedBytes.Add(uint64(length))
			continue // finite router queue loss, not a local send error
		}
		start := time.Now()
		if link.nextSend.After(start) {
			start = link.nextSend
		}
		serialization := time.Duration((int64(length)*int64(time.Second) + b.rate() - 1) / b.rate())
		link.nextSend = start.Add(serialization)
		// Borrowed buffers include magicsock/Geneve headroom. Preserve it and
		// the original logical endpoint for the eventual underlying Send.
		copyData := append([]byte(nil), data...)
		link.queue = append(link.queue, h3BulkLinkPacket{data: copyData, ep: ep, offset: offset, due: link.nextSend.Add(h3BulkLinkDelay)})
		link.bytes += length
		b.acceptedPackets.Add(1)
		b.acceptedBytes.Add(uint64(length))
		for previous := b.maxQueuedBytes.Load(); int64(link.bytes) > previous; previous = b.maxQueuedBytes.Load() {
			if b.maxQueuedBytes.CompareAndSwap(previous, int64(link.bytes)) {
				break
			}
		}
	}
	select {
	case link.wake <- struct{}{}:
	default:
	}
	return nil
}

func (link *h3BulkLink) run() {
	defer close(link.done)
	defer func() {
		link.mu.Lock()
		clear(link.queue)
		link.queue = nil
		link.bytes = 0
		link.mu.Unlock()
	}()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	bufs := make([][]byte, max(1, min(link.owner.Bind.BatchSize(), conn.IdealBatchSize)))
	for {
		link.mu.Lock()
		if link.ctx.Err() != nil {
			link.mu.Unlock()
			return
		}
		if link.head == len(link.queue) {
			link.queue = link.queue[:0]
			link.head = 0
			link.mu.Unlock()
			select {
			case <-link.ctx.Done():
				return
			case <-link.wake:
				continue
			}
		}
		packet := link.queue[link.head]
		if wait := time.Until(packet.due); wait > 0 {
			link.mu.Unlock()
			timer.Reset(wait)
			select {
			case <-link.ctx.Done():
				return
			case <-timer.C:
				continue
			}
		}
		// The scheduler must retain already-due batching. Turning every input
		// vector into singleton sends bypasses the real UDP batch path and can
		// make host syscall overhead look like a congestion-control limit.
		// Never wait to gather more packets or release a future packet early.
		now := time.Now()
		n, length := 0, 0
		comparable := packet.ep == nil || reflect.ValueOf(packet.ep).Comparable()
		for link.head < len(link.queue) && n < len(bufs) {
			next := link.queue[link.head]
			if n > 0 && (!comparable || next.ep != packet.ep || next.offset != packet.offset || next.due.After(now)) {
				break
			}
			bufs[n] = next.data
			n++
			length += len(next.data) - next.offset
			link.queue[link.head] = h3BulkLinkPacket{}
			link.head++
		}
		link.bytes -= length
		if link.head > 128 && link.head > len(link.queue)/2 {
			remaining := copy(link.queue, link.queue[link.head:])
			clear(link.queue[remaining:])
			link.queue = link.queue[:remaining]
			link.head = 0
		}
		link.mu.Unlock()
		link.owner.hostSendCalls.Add(1)
		link.owner.hostSendPackets.Add(uint64(n))
		if err := link.owner.Bind.Send(bufs[:n], packet.ep, packet.offset); err != nil {
			link.owner.sendErrors.Add(uint64(n))
		} else {
			link.owner.deliveredBytes.Add(uint64(length))
		}
		clear(bufs[:n])
	}
}

func (b *h3BulkShapedBind) snapshot() h3BulkLinkStats {
	snapshot := h3BulkLinkStats{AcceptedPackets: b.acceptedPackets.Load(), AcceptedBytes: b.acceptedBytes.Load(), DeliveredBytes: b.deliveredBytes.Load(), DroppedPackets: b.droppedPackets.Load(), DroppedBytes: b.droppedBytes.Load(), SendErrors: b.sendErrors.Load(), HostSendCalls: b.hostSendCalls.Load(), HostSendPackets: b.hostSendPackets.Load(), MaxQueuedBytes: b.maxQueuedBytes.Load()}
	b.mu.Lock()
	defer b.mu.Unlock()
	if link := b.current; link != nil {
		link.mu.Lock()
		snapshot.QueuedBytes = link.bytes
		link.mu.Unlock()
	}
	return snapshot
}

type h3BulkRecordedPacket struct {
	data   []byte
	offset int
	at     time.Time
}

type h3BulkRecordingBind struct {
	conn.Bind
	sent chan h3BulkRecordedPacket
}

func (*h3BulkRecordingBind) BatchSize() int { return 128 }

func (b *h3BulkRecordingBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, 1, nil
}
func (b *h3BulkRecordingBind) Close() error { return nil }
func (b *h3BulkRecordingBind) Send(bufs [][]byte, _ conn.Endpoint, offset int) error {
	for _, data := range bufs {
		b.sent <- h3BulkRecordedPacket{data: append([]byte(nil), data...), offset: offset, at: time.Now()}
	}
	return nil
}

func TestH3BulkLinkBoundsCopiesDelaysAndCancels(t *testing.T) {
	recorder := &h3BulkRecordingBind{sent: make(chan h3BulkRecordedPacket, 600)}
	bind := &h3BulkShapedBind{Bind: recorder}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	link := bind.current
	data := make([]byte, 1208)
	data[0], data[8] = 17, 42
	batch := make([][]byte, 600)
	for i := range batch {
		batch[i] = data
	}
	start := time.Now()
	if err := bind.Send(batch, nil, 8); err != nil {
		t.Fatal(err)
	}
	data[0], data[8] = 99, 99 // caller owns its buffer again immediately
	snapshot := bind.snapshot()
	if snapshot.AcceptedBytes != h3BulkLinkQueueBytes || snapshot.DroppedBytes != 120_000 || snapshot.MaxQueuedBytes != h3BulkLinkQueueBytes {
		t.Fatalf("finite FIFO accounting: %+v", snapshot)
	}
	select {
	case first := <-recorder.sent:
		if first.offset != 8 || first.data[0] != 17 || first.data[8] != 42 {
			t.Fatal("asynchronous link retained borrowed buffer or lost headroom")
		}
		if first.at.Sub(start) < h3BulkLinkDelay {
			t.Fatal("packet escaped the propagation delay")
		}
	case <-time.After(time.Second):
		t.Fatal("link did not deliver scheduled packet")
	}
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-link.done:
	default:
		t.Fatal("Close retained scheduler worker")
	}
	if link.bytes != 0 || len(link.queue) != 0 {
		t.Fatal("Close retained queued packet storage")
	}
	if err := bind.Send(batch[:1], nil, 8); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close = %v", err)
	}
	// A stopped generation must not poison a future Bind.Open.
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	if bind.current == link {
		t.Fatal("Open reused the canceled scheduler")
	}
}

func TestH3BulkLinkConcurrentSendAndClose(t *testing.T) {
	recorder := &h3BulkRecordingBind{sent: make(chan h3BulkRecordedPacket, 600)}
	bind := &h3BulkShapedBind{Bind: recorder}
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	link := bind.current
	started, finished := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		batch := [][]byte{make([]byte, 1208)}
		for range 2000 {
			if err := bind.Send(batch, nil, 8); err != nil {
				finished <- err
				return
			}
		}
		finished <- nil
	}()
	<-started
	if err := bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock concurrent Send")
	}
	if link.bytes != 0 || len(link.queue) != 0 {
		t.Fatal("concurrent sender appended after final queue drain")
	}
}

type h3BulkRecordedVector struct {
	data   [][]byte
	ep     conn.Endpoint
	offset int
	at     time.Time
}

type h3BulkVectorRecorder struct {
	conn.Bind
	calls chan h3BulkRecordedVector
}

func (*h3BulkVectorRecorder) BatchSize() int { return 2 }
func (b *h3BulkVectorRecorder) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	call := h3BulkRecordedVector{ep: ep, offset: offset, at: time.Now()}
	for _, buf := range bufs {
		call.data = append(call.data, append([]byte(nil), buf...))
	}
	b.calls <- call
	return nil
}

func TestH3BulkLinkReadyBatchBoundaries(t *testing.T) {
	b := &h3BulkVectorRecorder{calls: make(chan h3BulkRecordedVector, 8)}
	owner := &h3BulkShapedBind{Bind: b}
	ctx, cancel := context.WithCancel(context.Background())
	link := &h3BulkLink{owner: owner, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	plain := conn.NewStdNetBind()
	epA, err := plain.ParseEndpoint("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	epB, err := plain.ParseEndpoint("127.0.0.1:2")
	if err != nil {
		t.Fatal(err)
	}
	past, future := time.Now().Add(-time.Second), time.Now().Add(80*time.Millisecond)
	for i := range 6 {
		ep, offset, due := epA, 8, past
		if i >= 3 {
			ep = epB
		}
		if i >= 4 {
			offset = 4
		}
		if i == 5 {
			due = future
		}
		data := make([]byte, 12)
		data[offset] = byte(i + 1)
		link.queue = append(link.queue, h3BulkLinkPacket{data: data, ep: ep, offset: offset, due: due})
		link.bytes += len(data) - offset
	}
	go link.run()
	defer func() { cancel(); <-link.done }()
	seen := 0
	for index := 0; seen < 6; index++ {
		select {
		case call := <-b.calls:
			if index < 3 {
				want := []int{2, 1, 1}[index]
				if len(call.data) != want {
					t.Fatalf("batch %d size=%d want=%d", index, len(call.data), want)
				}
			} else if len(call.data) < 1 || len(call.data) > min(2, 6-seen) {
				t.Fatal("invalid final batch size")
			}
			wantEP, wantOffset := epA, 8
			if index >= 2 {
				wantEP = epB
			}
			if index >= 3 {
				wantOffset = 4
			}
			if call.ep != wantEP || call.offset != wantOffset {
				t.Fatal("mixed endpoint or offset")
			}
			for _, data := range call.data {
				seen++
				if seen == 6 && call.at.Before(future) {
					t.Fatal("future packet released early")
				}
				if len(data) != 12 || data[call.offset] != byte(seen) {
					t.Fatal("packet order or headroom changed")
				}
			}
		case <-time.After(time.Second):
			t.Fatal("ready batch stalled")
		}
	}
	if owner.hostSendPackets.Load() != 6 || owner.hostSendCalls.Load() < 4 || owner.hostSendCalls.Load() > 5 {
		t.Fatal("underlying host batch accounting mismatch")
	}
}

type h3BulkUncomparableEndpoint struct {
	conn.Endpoint
	data []byte
}

func TestH3BulkLinkUncomparableEndpoint(t *testing.T) {
	b := &h3BulkVectorRecorder{calls: make(chan h3BulkRecordedVector, 3)}
	ctx, cancel := context.WithCancel(context.Background())
	link := &h3BulkLink{owner: &h3BulkShapedBind{Bind: b}, ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
	ep := h3BulkUncomparableEndpoint{data: []byte{1}}
	for i := range 3 {
		link.queue = append(link.queue, h3BulkLinkPacket{data: []byte{byte(i)}, ep: ep, due: time.Now().Add(-time.Second)})
		link.bytes++
	}
	go link.run()
	defer func() { cancel(); <-link.done }()
	for i := range 3 {
		select {
		case call := <-b.calls:
			if len(call.data) != 1 || len(call.data[0]) != 1 || call.data[0][0] != byte(i) {
				t.Fatal("uncomparable endpoint must retain ordered singleton fallback")
			}
		case <-time.After(time.Second):
			t.Fatal("uncomparable endpoint stalled")
		}
	}
}
