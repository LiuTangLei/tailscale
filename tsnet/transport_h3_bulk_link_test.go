// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"errors"
	"net"
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
		link.queue[link.head] = h3BulkLinkPacket{}
		link.head++
		length := len(packet.data) - packet.offset
		link.bytes -= length
		if link.head > 128 && link.head > len(link.queue)/2 {
			remaining := copy(link.queue, link.queue[link.head:])
			clear(link.queue[remaining:])
			link.queue = link.queue[:remaining]
			link.head = 0
		}
		link.mu.Unlock()
		if err := link.owner.Bind.Send([][]byte{packet.data}, packet.ep, packet.offset); err != nil {
			link.owner.sendErrors.Add(1)
		} else {
			link.owner.deliveredBytes.Add(uint64(length))
		}
	}
}

func (b *h3BulkShapedBind) snapshot() h3BulkLinkStats {
	snapshot := h3BulkLinkStats{AcceptedPackets: b.acceptedPackets.Load(), AcceptedBytes: b.acceptedBytes.Load(), DeliveredBytes: b.deliveredBytes.Load(), DroppedPackets: b.droppedPackets.Load(), DroppedBytes: b.droppedBytes.Load(), SendErrors: b.sendErrors.Load(), MaxQueuedBytes: b.maxQueuedBytes.Load()}
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
