// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type nativeBulkResult struct {
	Direction                                                                                  string
	Bytes                                                                                      int64
	Seconds, Mbps                                                                              float64
	SHA256                                                                                     string
	UDP                                                                                        [2]repairUDPResult
	SendErrors, ReceiveDrops, RawDrops, OuterPackets, OuterBatchCalls, IPPackets, IPBatchCalls uint64
	AllocBytes, AllocObjects, TCPRetransmits, TCPTimeouts                                      uint64
}

// Only ready vectors are drained; no batching timer or kernel GSO is simulated.
// In particular, receive slabs are owned by each pump and reused, not allocated
// by the single-packet convenience helper on every packet.
func bulkNativeStacks(t *testing.T, pair *testPair) ([2]*stack.Stack, [2][4]byte) {
	t.Helper()
	for _, b := range pair.backends {
		b.host.Bind = &readyVectorTestBind{b.host.Bind}
	}
	fns := pair.open(t)
	ctx, cancel := context.WithCancel(t.Context())
	ips := [2][4]byte{{10, 89, 0, 1}, {10, 89, 0, 2}}
	var stacks [2]*stack.Stack
	var eps [2]*channel.Endpoint
	var wg sync.WaitGroup
	var errors atomic.Uint64
	for i := range 2 {
		stacks[i], eps[i] = repairLoadStack(t, ips[i])
		key := pair.keys[i^1].Public().Raw32()
		ep, err := pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(key[:]))
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			var packets [32]*stack.PacketBuffer
			var views [32]*buffer.View
			var data [32][]byte
			for {
				packets[0] = eps[i].ReadContext(ctx)
				if packets[0] == nil {
					return
				}
				n := 1
				for n < len(packets) {
					p := eps[i].Read()
					if p == nil {
						break
					}
					packets[n] = p
					n++
				}
				for j, p := range packets[:n] {
					views[j] = p.ToView()
					data[j] = views[j].AsSlice()
				}
				err := pair.backends[i].Bind().Send(data[:n], ep, 0)
				for j, p := range packets[:n] {
					views[j].Release()
					p.DecRef()
					views[j] = nil
					packets[j] = nil
					data[j] = nil
				}
				if err != nil {
					if ctx.Err() == nil {
						errors.Add(1)
					}
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			slab := make([]byte, 2*(1<<16-1))
			var packets [32]conn.ReceivedPacket
			for {
				n, err := fns[i](slab, packets[:])
				if err != nil {
					return
				}
				for _, p := range packets[:n] {
					if p.Size == 0 {
						continue
					}
					pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(p.Bytes(slab)))})
					eps[i].InjectInbound(header.IPv4ProtocolNumber, pkt)
					pkt.DecRef()
				}
			}
		}()
	}
	t.Cleanup(func() {
		cancel()
		for _, b := range pair.backends {
			b.Close()
		}
		wg.Wait()
		if n := errors.Load(); n != 0 {
			t.Errorf("native bridge send errors: %d", n)
		}
	})
	return stacks, ips
}

// The UDP population includes missing packets in unconditional P99. Receivers
// are stopped at the same fixed 1.5-second tail after bulk completion, not after
// a variant-dependent TCP cleanup period.
func bulkUDPProbe(t *testing.T, stacks [2]*stack.Stack, ips [2][4]byte) func() [2]repairUDPResult {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var sockets [2]*gonet.UDPConn
	var offered [2]atomic.Int64
	var wgSend, wgReceive sync.WaitGroup
	type observation struct {
		seq     int
		latency float64
	}
	var received [2][]observation
	var errors atomic.Uint64
	for i := range 2 {
		c, err := gonet.DialUDP(stacks[i], &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[i]), Port: 12000}, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[i^1]), Port: 12000}, header.IPv4ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		sockets[i] = c
		wgSend.Add(1)
		wgReceive.Add(1)
		go func() {
			defer wgSend.Done()
			tick := time.NewTicker(4 * time.Millisecond)
			defer tick.Stop()
			b := make([]byte, 256)
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					seq := offered[i].Add(1) - 1
					binary.BigEndian.PutUint64(b, uint64(seq))
					binary.BigEndian.PutUint64(b[8:], uint64(time.Now().UnixNano()))
					if _, err := c.Write(b); err != nil {
						errors.Add(1)
						return
					}
				}
			}
		}()
		go func() {
			defer wgReceive.Done()
			b := make([]byte, 512)
			for {
				n, err := c.Read(b)
				if err != nil {
					return
				}
				if n != 256 {
					errors.Add(1)
					continue
				}
				received[i] = append(received[i], observation{int(binary.BigEndian.Uint64(b)), float64(time.Now().UnixNano()-int64(binary.BigEndian.Uint64(b[8:]))) / 1e6})
			}
		}()
	}
	var once sync.Once
	var result [2]repairUDPResult
	stop := func() [2]repairUDPResult {
		once.Do(func() {
			end := time.Now().Add(1500 * time.Millisecond)
			cancel()
			wgSend.Wait()
			if left := time.Until(end); left > 0 {
				time.Sleep(left)
			}
			for _, c := range sockets {
				c.Close()
			}
			wgReceive.Wait()
			for i := range 2 {
				r := &result[i]
				r.Offered = int(offered[i].Load())
				seen := make(map[int]bool)
				high := -1
				var latencies []float64
				for _, o := range received[i^1] {
					if o.seq < 0 || o.seq >= r.Offered {
						errors.Add(1)
						continue
					}
					if seen[o.seq] {
						r.Duplicates++
						continue
					}
					seen[o.seq] = true
					if o.seq < high {
						r.Reordered++
					}
					high = max(high, o.seq)
					latencies = append(latencies, o.latency)
				}
				r.Delivered = len(seen)
				r.Missing = r.Offered - r.Delivered
				slices.Sort(latencies)
				if len(latencies) > 0 {
					r.P50MS = latencies[(len(latencies)-1)*50/100]
					r.P95MS = latencies[(len(latencies)-1)*95/100]
					r.P99MS = latencies[(len(latencies)-1)*99/100]
				}
				rank := (r.Offered*99+99)/100 - 1
				if rank >= 0 && rank < len(latencies) {
					v := latencies[rank]
					r.UnconditionalP99MS = &v
				}
			}
			if n := errors.Load(); n != 0 {
				t.Errorf("UDP probe errors: %d", n)
			}
		})
		return result
	}
	t.Cleanup(func() { stop() })
	return stop
}

func TestH3NativeOneGiBBulk(t *testing.T) {
	if os.Getenv("TS_H3_BULK") != "1" {
		t.Skip("set TS_H3_BULK=1 for bounded one-GiB native TCP throughput")
	}
	size := int64(1 << 30)
	if v := os.Getenv("TS_H3_BULK_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 || n > size {
			t.Fatal("invalid bulk byte limit")
		}
		size = n
	}
	var results []nativeBulkResult
	defer func() {
		b, _ := json.MarshalIndent(results, "", "  ")
		t.Logf("NATIVE_BULK_RESULTS=%s", b)
		if path := os.Getenv("TS_H3_BULK_RESULT"); path != "" {
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Error(err)
			}
		}
	}()
	for from := range 2 {
		t.Run(fmt.Sprintf("direction%d", from), func(t *testing.T) { results = append(results, runNativeBulk(t, from, size)) })
	}
}

func runNativeBulk(t *testing.T, from int, size int64) nativeBulkResult {
	t.Helper()
	pair := newTestPair(t, "http3-magicsock") // TCP repair and FEC are disabled.
	stacks, ips := bulkNativeStacks(t, pair)
	to := from ^ 1
	listener, err := gonet.ListenTCP(stacks[to], tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[to]), Port: 8080}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	client, err := gonet.DialContextTCP(ctx, stacks[from], tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[to]), Port: 8080}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	deadline := time.Now().Add(10 * time.Minute)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	block := make([]byte, 64<<10)
	for i := range block {
		block[i] = byte(i*31 + i/256)
	}
	expected := sha256.New()
	for n := size; n > 0; {
		k := min(n, int64(len(block)))
		expected.Write(block[:k])
		n -= k
	}
	stopUDP := bulkUDPProbe(t, stacks, ips)
	type received struct {
		n    int64
		hash string
		end  time.Time
		err  error
	}
	done := make(chan received, 1)
	// Reuse application buffers and continuously fill TCP's own window. There is
	// no per-chunk echo, artificial data ACK, concurrent bulk, Range or retry.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	go func() {
		h := sha256.New()
		n, err := io.CopyBuffer(h, io.LimitReader(server, size), make([]byte, 64<<10))
		done <- received{n, hex.EncodeToString(h.Sum(nil)), time.Now(), err}
	}()
	for n := size; n > 0; {
		k := min(n, int64(len(block)))
		written, err := client.Write(block[:k])
		if err != nil {
			t.Fatal(err)
		}
		n -= int64(written)
	}
	got := <-done
	runtime.ReadMemStats(&after)
	seconds := got.end.Sub(start).Seconds()
	if got.err != nil || got.n != size || got.hash != hex.EncodeToString(expected.Sum(nil)) {
		t.Fatalf("bulk integrity: received=%d expected=%d hash=%s err=%v", got.n, size, got.hash, got.err)
	}
	r := nativeBulkResult{Direction: fmt.Sprintf("%d->%d", from, to), Bytes: got.n, SHA256: got.hash, Seconds: seconds, Mbps: float64(got.n) * 8 / seconds / 1e6, UDP: stopUDP(), AllocBytes: after.TotalAlloc - before.TotalAlloc, AllocObjects: after.Mallocs - before.Mallocs}
	for _, st := range stacks {
		r.TCPRetransmits += st.Stats().TCP.Retransmits.Value()
		r.TCPTimeouts += st.Stats().TCP.Timeouts.Value()
	}
	for _, b := range pair.backends {
		c := &b.counters
		r.SendErrors += c.SendErrors.Load()
		r.ReceiveDrops += c.ReceiveQueueDrops.Load()
		r.RawDrops += c.RawPacketsDropped.Load()
		r.OuterPackets += c.RawBatchPackets.Load()
		r.OuterBatchCalls += c.RawWriteBatches.Load()
		r.IPPackets += c.IPBatchPackets.Load()
		r.IPBatchCalls += c.IPBatchCalls.Load()
	}
	t.Logf("BULK %s: %d bytes %.3fs %.3f Mbps SHA256=%s drops=%d sendErrors=%d", r.Direction, r.Bytes, r.Seconds, r.Mbps, r.SHA256, r.ReceiveDrops, r.SendErrors)
	return r
}
