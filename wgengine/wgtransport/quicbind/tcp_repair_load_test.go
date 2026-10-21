// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
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
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Actual inner TCP/UDP sockets over the native IP DATAGRAM path. This is not
// the embedded H3 CONNECT byte-stream test. All shaping is local and bounded.
type repairLoadLink struct {
	conn.Bind
	rate           int64
	delay          time.Duration
	burst, reorder bool
	enabled        atomic.Bool
	mu             sync.Mutex
	next           time.Time
	seq            uint64
	queue          chan loadLinkPacket
	slots          chan struct{}
	done           chan struct{}
	once           sync.Once
	drops          atomic.Uint64
	writeErrors    atomic.Uint64
}
type repairLoadHeap []loadLinkPacket

func (h repairLoadHeap) Len() int           { return len(h) }
func (h repairLoadHeap) Less(i, j int) bool { return h[i].due.Before(h[j].due) }
func (h repairLoadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *repairLoadHeap) Push(v any)        { *h = append(*h, v.(loadLinkPacket)) }
func (h *repairLoadHeap) Pop() any          { a := *h; v := a[len(a)-1]; *h = a[:len(a)-1]; return v }
func (l *repairLoadLink) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	f, p, e := l.Bind.Open(port)
	if e != nil {
		return f, p, e
	}
	l.queue = make(chan loadLinkPacket, 64)
	l.slots = make(chan struct{}, 64)
	l.done = make(chan struct{})
	go func() {
		h := &repairLoadHeap{}
		heap.Init(h)
		timer := time.NewTimer(time.Hour)
		defer timer.Stop()
		for {
			var fire <-chan time.Time
			if h.Len() > 0 {
				timer.Reset(max(time.Until((*h)[0].due), 0))
				fire = timer.C
			}
			select {
			case <-l.done:
				return
			case p := <-l.queue:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				heap.Push(h, p)
			case <-fire:
				p := heap.Pop(h).(loadLinkPacket)
				if e := l.Bind.Send([][]byte{p.data}, p.endpoint, 0); e != nil {
					l.writeErrors.Add(1)
				}
				<-l.slots
			}
		}
	}()
	return f, p, nil
}
func (l *repairLoadLink) Close() error {
	l.once.Do(func() {
		if l.done != nil {
			close(l.done)
		}
	})
	return l.Bind.Close()
}
func (l *repairLoadLink) Send(packets [][]byte, ep conn.Endpoint, offset int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, raw := range packets {
		l.seq++
		active := l.enabled.Load()
		if active && l.burst && l.seq%1009 < 3 {
			l.drops.Add(1)
			continue
		}
		select {
		case l.slots <- struct{}{}:
		default:
			l.drops.Add(1)
			continue
		}
		now := time.Now()
		if l.next.Before(now) {
			l.next = now
		}
		l.next = l.next.Add(time.Duration(len(raw)-offset) * time.Second / time.Duration(l.rate))
		due := l.next.Add(l.delay)
		if active && l.reorder && l.seq%37 == 0 {
			due = due.Add(24 * time.Millisecond)
		}
		select {
		case l.queue <- loadLinkPacket{bytes.Clone(raw[offset:]), ep, due}:
		case <-l.done:
			<-l.slots
			return net.ErrClosed
		}
	}
	return nil
}

type repairUDPResult struct {
	Offered, Delivered, Missing, Duplicates, Reordered int
	P50MS, P95MS, P99MS                                float64
	UnconditionalP99MS                                 *float64
}
type repairLoadResult struct {
	Scenario                                                                                                         string
	Trial                                                                                                            int
	Enabled                                                                                                          bool
	UDP                                                                                                              [2]repairUDPResult
	TCPBytes                                                                                                         int64
	OriginalBytes, ControlBytes, RepairPackets, TailProbes, RepairBytes, SuppressedDuplicates, LinkDrops, LocalDrops uint64
}

func repairLoadStack(t *testing.T, ip [4]byte) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	ep := channel.New(256, 1280, "")
	if e := s.CreateNIC(1, ep); e != nil {
		t.Fatal(e)
	}
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: header.IPv4ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(ip).WithPrefix()}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	t.Cleanup(func() { ep.Close(); s.Close(); s.Wait() })
	return s, ep
}

func runTCPRepairLoad(t *testing.T, scenario string, enabled bool, trial int, duration time.Duration) repairLoadResult {
	t.Helper()
	out := repairLoadResult{Scenario: scenario, Enabled: enabled, Trial: trial}
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.TCPRepair = enabled })
	for _, b := range pair.backends {
		b.host.Bind = &readyVectorTestBind{b.host.Bind}
	}
	var links [2]*repairLoadLink
	for i := range links {
		if scenario == "unshaped" {
			continue
		}
		rate, delay := int64(1500000), 8*time.Millisecond
		if scenario == "asymmetric" {
			rate, delay = 750000, 6*time.Millisecond
			if i == 1 {
				rate, delay = 150000, 22*time.Millisecond
			}
		}
		links[i] = &repairLoadLink{Bind: pair.bases[i].Bind, rate: rate, delay: delay, burst: scenario != "reorder", reorder: scenario != "burst"}
		pair.bases[i].Bind = links[i]
	}
	fns := pair.open(t)
	ctx, cancel := context.WithTimeout(t.Context(), duration+10*time.Second)
	defer cancel()
	var stacks [2]*stack.Stack
	var eps [2]*channel.Endpoint
	var endpoints [2]conn.Endpoint
	ips := [2][4]byte{{10, 88, 0, 1}, {10, 88, 0, 2}}
	var wg sync.WaitGroup
	var bridgeErrors atomic.Uint64
	for i := range 2 {
		stacks[i], eps[i] = repairLoadStack(t, ips[i])
		key := pair.keys[i^1].Public().Raw32()
		var e error
		endpoints[i], e = pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(key[:]))
		if e != nil {
			t.Fatal(e)
		}
		p, e := pair.backends[i].active.Load().peer(key, nil)
		if e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			s, e := p.getSessionContext(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			if (s.dgram.(*http3Channel).repair != nil) != enabled {
				t.Fatal("repair negotiation mismatch")
			}
		}
	}
	for i := range 2 {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			var packets [32]*stack.PacketBuffer
			var views [32]*buffer.View
			var payloads [32][]byte
			for {
				packets[0] = eps[i].ReadContext(ctx)
				if packets[0] == nil {
					return
				}
				n := 1
				// Drain only packets already available. This mirrors a ready
				// TUN batch and adds no coalescing timer or UDP wait.
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
					payloads[j] = views[j].AsSlice()
				}
				e := pair.backends[i].Bind().Send(payloads[:n], endpoints[i], 0)
				for j, p := range packets[:n] {
					views[j].Release()
					p.DecRef()
					packets[j] = nil
					views[j] = nil
					payloads[j] = nil
				}
				if e != nil {
					if ctx.Err() == nil {
						bridgeErrors.Add(1)
					}
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			buf := make([]byte, maxPacket)
			sizes := make([]int, 1)
			endpoints := make([]conn.Endpoint, 1)
			for {
				_, e := receiveTestSlots(fns[i], [][]byte{buf}, sizes, endpoints)
				if e != nil {
					return
				}
				if sizes[0] == 0 {
					continue
				}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(buf[:sizes[0]]))})
				eps[i].InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}()
	}
	defer func() {
		cancel()
		for _, b := range pair.backends {
			b.Close()
		}
		wg.Wait()
	}()
	listener, e := gonet.ListenTCP(stacks[1], tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[1]), Port: 8080}, header.IPv4ProtocolNumber)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	var tcpWG sync.WaitGroup
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			tcpWG.Add(1)
			go func() { defer tcpWG.Done(); defer c.Close(); io.Copy(c, c) }()
		}
	}()
	var udpConns [2]*gonet.UDPConn
	for i := range 2 {
		c, e := gonet.DialUDP(stacks[i], &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[i]), Port: 12000}, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[i^1]), Port: 12000}, header.IPv4ProtocolNumber)
		if e != nil {
			t.Fatal(e)
		}
		udpConns[i] = c
		defer c.Close()
	}
	type observation struct {
		seq     int
		latency time.Duration
	}
	var observations [2][]observation
	var receiveWG sync.WaitGroup
	for i := range 2 {
		i := i
		receiveWG.Add(1)
		go func() {
			defer receiveWG.Done()
			b := make([]byte, 512)
			for {
				n, e := udpConns[i].Read(b)
				if e != nil {
					return
				}
				if n != 256 {
					continue
				}
				observations[i] = append(observations[i], observation{int(binary.BigEndian.Uint64(b)), time.Duration(time.Now().UnixNano() - int64(binary.BigEndian.Uint64(b[8:])))})
			}
		}()
	}
	// Warm the sockets and handshake before applying impairment or measuring.
	var clients []net.Conn
	for range 3 {
		c, e := gonet.DialContextTCP(ctx, stacks[0], tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(ips[1]), Port: 8080}, header.IPv4ProtocolNumber)
		if e != nil {
			t.Fatal(e)
		}
		clients = append(clients, c)
	}
	for _, l := range links {
		if l == nil {
			continue
		}
		l.enabled.Store(true)
	}
	var tcpBytes atomic.Int64
	var clientWG sync.WaitGroup
	errors := make(chan error, 8)
	stop := time.Now().Add(duration)
	for index, c := range clients {
		index, c := index, c
		clientWG.Add(1)
		go func() {
			defer clientWG.Done()
			defer c.Close()
			c.SetDeadline(stop.Add(time.Second))
			payload := bytes.Repeat([]byte{byte(index + 1)}, 16<<10)
			received := make([]byte, len(payload))
			iteration := 0
			for time.Now().Before(stop) {
				n := len(payload)
				if iteration%8 == 0 {
					n = 64
				}
				iteration++
				binary.BigEndian.PutUint64(payload, uint64(iteration))
				if _, e := c.Write(payload[:n]); e != nil {
					if time.Now().Before(stop) {
						errors <- e
					}
					return
				}
				if _, e := io.ReadFull(c, received[:n]); e != nil {
					if time.Now().Before(stop) {
						errors <- e
					}
					return
				}
				if !bytes.Equal(payload[:n], received[:n]) {
					errors <- fmt.Errorf("TCP payload mismatch")
					return
				}
				if time.Now().Before(stop) {
					tcpBytes.Add(int64(n))
				}
			}
		}()
	}
	var offered [2]atomic.Int64
	var sendWG sync.WaitGroup
	for i := range 2 {
		i := i
		sendWG.Add(1)
		go func() {
			defer sendWG.Done()
			ticker := time.NewTicker(4 * time.Millisecond)
			defer ticker.Stop()
			b := make([]byte, 256)
			for time.Now().Before(stop) {
				<-ticker.C
				seq := offered[i].Add(1) - 1
				binary.BigEndian.PutUint64(b, uint64(seq))
				binary.BigEndian.PutUint64(b[8:], uint64(time.Now().UnixNano()))
				if _, e := udpConns[i].Write(b); e != nil {
					errors <- e
					return
				}
			}
		}()
	}
	sendWG.Wait()
	clientWG.Wait()
	// Use the same observation deadline in both modes. Waiting a fixed
	// amount after TCP completion would give slower TCP runs more UDP drain.
	if drain := time.Until(stop.Add(1500 * time.Millisecond)); drain > 0 {
		time.Sleep(drain)
	}
	for _, c := range udpConns {
		c.Close()
	}
	receiveWG.Wait()
	listener.Close()
	for _, c := range clients {
		c.Close()
	}
	// Closing the backend below cancels any outstanding server echo read.
	for _, s := range stacks {
		s.Close()
	}
	tcpWG.Wait()
	close(errors)
	for e := range errors {
		t.Error(e)
	}
	if bridgeErrors.Load() != 0 {
		t.Errorf("native IP bridge send errors: %d", bridgeErrors.Load())
	}
	out.TCPBytes = tcpBytes.Load()
	if out.TCPBytes == 0 {
		t.Error("no verified inner TCP payload")
	}
	for direction := range 2 {
		r := &out.UDP[direction]
		r.Offered = int(offered[direction].Load())
		seen := make(map[int]bool)
		latencies := make([]float64, 0, r.Offered)
		highest := -1
		for _, o := range observations[direction^1] {
			if seen[o.seq] {
				r.Duplicates++
				continue
			}
			seen[o.seq] = true
			if o.seq < highest {
				r.Reordered++
			}
			highest = max(highest, o.seq)
			latencies = append(latencies, float64(o.latency)/float64(time.Millisecond))
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
	for i, b := range pair.backends {
		c := &b.counters
		out.OriginalBytes += c.TCPRepairOriginalBytes.Load()
		out.ControlBytes += c.TCPRepairControlBytes.Load()
		out.RepairPackets += c.TCPRepairPackets.Load()
		out.TailProbes += c.TCPRepairTailProbes.Load()
		out.RepairBytes += c.TCPRepairBytes.Load()
		out.SuppressedDuplicates += c.TCPRepairDuplicates.Load()
		out.LocalDrops += c.ReceiveQueueDrops.Load()
		if links[i] != nil {
			out.LinkDrops += links[i].drops.Load()
			if links[i].writeErrors.Load() != 0 {
				t.Error("unexpected outer socket write error")
			}
		}
	}
	if out.RepairBytes > out.OriginalBytes/20+1024 {
		t.Error("repair exceeded admitted-data budget")
	}
	return out
}

func TestTCPRepairNativeMixedLoad(t *testing.T) {
	if os.Getenv("TS_H3_REPAIR_LOAD") != "1" {
		t.Skip("set TS_H3_REPAIR_LOAD=1 for native TCP/UDP impairment acceptance")
	}
	duration := 5 * time.Second
	if v, e := strconv.Atoi(os.Getenv("TS_H3_REPAIR_SECONDS")); e == nil && v > 0 {
		duration = time.Duration(v) * time.Second
	}
	trials := 3
	if v, e := strconv.Atoi(os.Getenv("TS_H3_REPAIR_TRIALS")); e == nil && v > 0 {
		trials = v
	}
	var results []repairLoadResult
	defer func() {
		data, _ := json.MarshalIndent(results, "", "  ")
		t.Logf("NATIVE_REPAIR_RESULTS=%s", data)
		if path := os.Getenv("TS_H3_REPAIR_RESULT"); path != "" {
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Error(e)
			}
		}
	}()
	for _, scenario := range []string{"burst", "reorder", "asymmetric"} {
		for trial := range trials {
			// Alternate order to avoid consistently giving one mode the warm machine.
			order := []bool{false, true}
			if trial%2 != 0 {
				order = []bool{true, false}
			}
			for _, enabled := range order {
				t.Run(fmt.Sprintf("%s/trial%d/repair_%t", scenario, trial, enabled), func(t *testing.T) { results = append(results, runTCPRepairLoad(t, scenario, enabled, trial, duration)) })
			}
		}
	}
	// Report the gate separately from functional correctness. A failed gate
	// leaves this experimental feature opt-in; it never changes the default.
	gate := len(results) == 3*trials*2
	for _, base := range results {
		if base.Enabled {
			continue
		}
		for _, on := range results {
			if !on.Enabled || on.Scenario != base.Scenario || on.Trial != base.Trial {
				continue
			}
			for d := range 2 {
				a, b := base.UDP[d], on.UDP[d]
				lossA := float64(a.Missing) / float64(max(a.Offered, 1))
				lossB := float64(b.Missing) / float64(max(b.Offered, 1))
				if b.Duplicates != 0 || lossB > lossA+0.005 || a.UnconditionalP99MS == nil || b.UnconditionalP99MS == nil || *b.UnconditionalP99MS > max(*a.UnconditionalP99MS*1.10, *a.UnconditionalP99MS+5) {
					gate = false
				}
			}
		}
	}
	if !gate {
		t.Error("UDP nonregression gate failed; keep TCP repair disabled")
	}
	t.Logf("UDP_NONREGRESSION_GATE=%t (loss delta <=0.5pp, finite unconditional P99 <=max(baseline*1.10,baseline+5ms), no duplicates)", gate)
}
