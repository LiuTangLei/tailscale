// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
)

// blastResult is one unidirectional carrier measurement. It reports what the
// receiver actually obtained, never what the sender offered.
type blastResult struct {
	Mode            string  `json:"mode"`
	PacketBytes     int     `json:"packet_bytes"`
	Batch           int     `json:"batch"`
	Seconds         float64 `json:"seconds"`
	SentPackets     uint64  `json:"sent_packets"`
	ReceivedPackets uint64  `json:"received_packets"`
	DeliveredMbps   float64 `json:"delivered_mbps"`
	DeliveredPPS    float64 `json:"delivered_pps"`
	LossPercent     float64 `json:"loss_percent"`
	SendCalls       uint64  `json:"send_calls"`
	ReceiveCalls    uint64  `json:"receive_calls"`
	ReceiveBatch    float64 `json:"receive_batch_avg"`
	OuterBatch      float64 `json:"outer_write_batch_avg,omitempty"`
	Fragmented      uint64  `json:"fragmented_packets,omitempty"`
	EnqueueWaits    uint64  `json:"enqueue_waits,omitempty"`
}

func blastEnvInt(name string, fallback int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil && n > 0 {
		return n
	}
	return fallback
}

// TestCarrierBlast is an opt-in loopback measurement of the carrier itself:
// ready batches of opaque IP-sized packets go into Bind.Send and are counted
// at the peer's ReceiveFunc. There is no inner TCP, TUN or shaper, so the
// number isolates carrier CPU cost and send admission (pacing/congestion).
// mode "raw" sends the same batches over the bare host Bind as a reference
// for what the socket path alone can carry on this machine.
//
//	TS_H3_BLAST=1 TS_H3_BLAST_MODE=http3-magicsock go test -run TestCarrierBlast -v
func TestCarrierBlast(t *testing.T) {
	if os.Getenv("TS_H3_BLAST") != "1" {
		t.Skip("set TS_H3_BLAST=1 for the carrier loopback measurement")
	}
	mode := os.Getenv("TS_H3_BLAST_MODE")
	if mode == "" {
		mode = "http3-magicsock"
	}
	size := blastEnvInt("TS_H3_BLAST_BYTES", 1100)
	batch := blastEnvInt("TS_H3_BLAST_BATCH", 16)
	seconds := blastEnvInt("TS_H3_BLAST_SECONDS", 5)
	initial := blastEnvInt("TS_H3_BLAST_INITIAL", 1200)
	if batch > conn.IdealBatchSize {
		batch = conn.IdealBatchSize
	}

	var send func([][]byte) error
	var receive conn.ReceiveFunc
	var counters *Counters
	if mode == "raw" {
		var binds [2]conn.Bind
		var ports [2]uint16
		var fns [2][]conn.ReceiveFunc
		for i := range binds {
			binds[i] = conn.NewDefaultBind()
			var err error
			fns[i], ports[i], err = binds[i].Open(0)
			if err != nil {
				t.Fatal(err)
			}
			b := binds[i]
			t.Cleanup(func() { b.Close() })
		}
		ep, err := binds[0].ParseEndpoint(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(ports[1]))))
		if err != nil {
			t.Fatal(err)
		}
		send = func(bufs [][]byte) error { return binds[0].Send(bufs, ep, 0) }
		receive = fns[1][0]
		batch = min(batch, binds[0].BatchSize())
	} else {
		pair := newTestPair(t, mode, func(c *Config) { c.InitialPacketSize = uint16(initial) })
		fns := pair.open(t)
		key := pair.keys[1].Public().Raw32()
		ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(key[:]))
		if err != nil {
			t.Fatal(err)
		}
		bind := pair.backends[0].Bind()
		// A ready batch can never exceed what the host Bind accepts (1 on
		// platforms without sendmmsg).
		batch = min(batch, bind.BatchSize())
		send = func(bufs [][]byte) error { return bind.Send(bufs, ep, 0) }
		receive = fns[1]
		counters = pair.backends[0].Counters()
		// Establish the session before the measured interval.
		if err := send([][]byte{make([]byte, 64)}); err != nil {
			t.Fatal(err)
		}
		readOne(t, receive)
	}

	var receivedPackets, receivedBytes, receiveCalls atomic.Uint64
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		slab := make([]byte, 2*(1<<16-1))
		packets := make([]conn.ReceivedPacket, conn.IdealBatchSize)
		for {
			n, err := receive(slab, packets)
			if err != nil {
				return
			}
			receiveCalls.Add(1)
			for _, p := range packets[:n] {
				if p.Size > 0 {
					receivedPackets.Add(1)
					receivedBytes.Add(uint64(p.Size))
				}
			}
		}
	}()

	if path := os.Getenv("TS_H3_BLAST_CPUPROFILE"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			t.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	buffers := make([][]byte, batch)
	for i := range buffers {
		buffers[i] = make([]byte, size)
		buffers[i][0] = 0x45 // plausible IPv4 header start; payload is opaque
	}
	var before Counters
	snapshot := func(dst *Counters) {
		if counters == nil {
			return
		}
		dst.RawWriteBatches.Store(counters.RawWriteBatches.Load())
		dst.RawBatchPackets.Store(counters.RawBatchPackets.Load())
		dst.FragmentedPackets.Store(counters.FragmentedPackets.Load())
		dst.EnqueueWaits.Store(counters.EnqueueWaits.Load())
	}
	snapshot(&before)
	baseReceived, baseBytes, baseCalls := receivedPackets.Load(), receivedBytes.Load(), receiveCalls.Load()
	var sent, calls, sequence, rejected uint64
	var firstError error
	started := time.Now()
	deadline := started.Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		for _, b := range buffers {
			sequence++
			binary.BigEndian.PutUint64(b[20:], sequence)
		}
		if err := send(buffers); err != nil {
			// Bounded-queue rejection is carrier backpressure, not a failure.
			if firstError == nil {
				firstError = err
			}
			rejected++
			continue
		}
		calls++
		sent += uint64(batch)
	}
	elapsed := time.Since(started)
	if rejected > 0 {
		t.Logf("%d send calls were rejected; first error: %v", rejected, firstError)
	}
	if sent == 0 {
		t.Fatalf("no batch was accepted: %v", firstError)
	}
	// Let in-flight packets land before reading the receive counters.
	time.Sleep(200 * time.Millisecond)
	out := blastResult{Mode: mode, PacketBytes: size, Batch: batch, Seconds: elapsed.Seconds(), SentPackets: sent, SendCalls: calls}
	out.ReceivedPackets = receivedPackets.Load() - baseReceived
	out.ReceiveCalls = receiveCalls.Load() - baseCalls
	out.DeliveredMbps = float64(receivedBytes.Load()-baseBytes) * 8 / elapsed.Seconds() / 1e6
	out.DeliveredPPS = float64(out.ReceivedPackets) / elapsed.Seconds()
	if sent > 0 && out.ReceivedPackets <= sent {
		out.LossPercent = 100 * float64(sent-out.ReceivedPackets) / float64(sent)
	}
	if out.ReceiveCalls > 0 {
		out.ReceiveBatch = float64(out.ReceivedPackets) / float64(out.ReceiveCalls)
	}
	if counters != nil {
		var after Counters
		snapshot(&after)
		if writes := after.RawWriteBatches.Load() - before.RawWriteBatches.Load(); writes > 0 {
			out.OuterBatch = float64(after.RawBatchPackets.Load()-before.RawBatchPackets.Load()) / float64(writes)
		}
		out.Fragmented = after.FragmentedPackets.Load() - before.FragmentedPackets.Load()
		out.EnqueueWaits = after.EnqueueWaits.Load() - before.EnqueueWaits.Load()
	}
	data, _ := json.Marshal(out)
	t.Logf("BLAST_RESULT=%s", data)
	if path := os.Getenv("TS_H3_BLAST_RESULT"); path != "" {
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Error(err)
		}
	}
}
