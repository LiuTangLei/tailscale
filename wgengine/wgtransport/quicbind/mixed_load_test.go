// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/net/packet"
)

// A test-only duplex link: each direction has independent serialization,
// propagation, deterministic loss and a bounded queue. It changes no host route.
type loadLinkPacket struct {
	data     []byte
	endpoint conn.Endpoint
	due      time.Time
}
type loadLink struct {
	conn.Bind
	mu       sync.Mutex
	next     time.Time
	queue    chan loadLinkPacket
	done     chan struct{}
	once     sync.Once
	sequence atomic.Uint64
	drops    atomic.Uint64
}

func (l *loadLink) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	f, p, e := l.Bind.Open(port)
	if e != nil {
		return f, p, e
	}
	l.queue = make(chan loadLinkPacket, 64)
	l.done = make(chan struct{})
	go func() {
		for {
			select {
			case <-l.done:
				return
			case p := <-l.queue:
				timer := time.NewTimer(time.Until(p.due))
				select {
				case <-l.done:
					timer.Stop()
					return
				case <-timer.C:
				}
				_ = l.Bind.Send([][]byte{p.data}, p.endpoint, 0)
			}
		}
	}()
	return f, p, nil
}
func (l *loadLink) Close() error {
	l.once.Do(func() {
		if l.done != nil {
			close(l.done)
		}
	})
	return l.Bind.Close()
}
func (l *loadLink) Send(packets [][]byte, ep conn.Endpoint, offset int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, data := range packets {
		// 0.5% deterministic outer UDP loss, including handshake packets.
		if l.sequence.Add(1)%197 == 0 {
			l.drops.Add(1)
			continue
		}
		now := time.Now()
		if l.next.Before(now) {
			l.next = now
		}
		end := l.next.Add(time.Duration(len(data)-offset) * time.Second / 1500000) // 12 Mbit/s
		p := loadLinkPacket{bytes.Clone(data[offset:]), ep, end.Add(8 * time.Millisecond)}
		select {
		case l.queue <- p:
			l.next = end
		default:
			l.drops.Add(1)
		}
	}
	return nil
}

type mixedLoadResult struct {
	Mode                                               string `json:"mode"`
	Offered, Delivered, Missing, Duplicates, Reordered int
	P50MS, P95MS, P99MS, MaxMS                         float64
	UnconditionalP99MS                                 *float64
	TCPBytes                                           int64
	DurationSeconds                                    float64
	LinkDrops                                          uint64
	ReconnectMS                                        []float64
	EarlyAccepted, EarlyRejected                       uint64
}

// Opt in: this is a reproducible load acceptance, not a timing-sensitive unit
// test. Both windows include the same offered UDP traffic and three reconnects.
func TestMixedTCPUDPResumptionLoad(t *testing.T) {
	if os.Getenv("TS_H3_MIXED_LOAD") != "1" {
		t.Skip("set TS_H3_MIXED_LOAD=1 for controlled load acceptance")
	}
	var results []mixedLoadResult
	for _, early := range []bool{false, true} {
		name := map[bool]string{false: "full_handshake", true: "zero_rtt"}[early]
		t.Run(name, func(t *testing.T) {
			index := 0
			pair := newTestPair(t, "http3-magicsock", func(c *Config) {
				c.AutoTrust, c.TCPStreams, c.Peers = true, true, nil
				c.Server = index == 1
				c.TCPNodeAddress = tcpTestAddress
				if index == 1 {
					c.TCPHandler = func(_ [32]byte, _ netip.AddrPort) func(net.Conn) {
						return func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }
					}
				}
				index++
			})
			var links [2]*loadLink
			for i := range links {
				links[i] = &loadLink{Bind: pair.bases[i].Bind}
				pair.bases[i].Bind = links[i]
			}
			fns := pair.open(t)
			b := pair.backends[0]
			remote := pair.keys[1].Public().Raw32()
			p, e := b.active.Load().peer(remote, nil)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			session, e := p.getSessionContext(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			cache := b.clientSessionCache(remote)
			waitTicket(t, cache)
			endpoint, e := b.Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
			if e != nil {
				t.Fatal(e)
			}
			type observation struct {
				sequence int
				latency  time.Duration
			}
			var observations []observation
			var receiveMu sync.Mutex
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				buf := make([]byte, maxPacket)
				sizes := make([]int, 1)
				eps := make([]conn.Endpoint, 1)
				for {
					_, e := receiveTestSlots(fns[1], [][]byte{buf}, sizes, eps)
					if e != nil {
						return
					}
					if sizes[0] < 44 {
						continue
					}
					payload := buf[28:sizes[0]]
					seq := int(binary.BigEndian.Uint64(payload))
					sent := int64(binary.BigEndian.Uint64(payload[8:]))
					o := observation{seq, time.Duration(time.Now().UnixNano() - sent)}
					receiveMu.Lock()
					observations = append(observations, o)
					receiveMu.Unlock()
				}
			}()
			var offered atomic.Int64
			sendDone := make(chan struct{})
			stopSend := make(chan struct{})
			sendErrors := make(chan error, 1)
			started := time.Now()
			go func() {
				defer close(sendDone)
				ticker := time.NewTicker(4 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-stopSend:
						return
					case <-ctx.Done():
						return
					case <-ticker.C:
						seq := offered.Add(1) - 1
						payload := make([]byte, 256)
						binary.BigEndian.PutUint64(payload, uint64(seq))
						binary.BigEndian.PutUint64(payload[8:], uint64(time.Now().UnixNano()))
						h := &packet.UDP4Header{IP4Header: packet.IP4Header{Src: netip.MustParseAddr("10.88.0.1"), Dst: netip.MustParseAddr("10.88.0.2")}, SrcPort: 12000, DstPort: 12001}
						if e := b.Bind().Send([][]byte{packet.Generate(h, payload)}, endpoint, 0); e != nil {
							select {
							case sendErrors <- e:
							default:
							}
							return
						}
					}
				}
			}()
			var tcpBytes atomic.Int64
			r := mixedLoadResult{Mode: name}
			for epoch := range 3 {
				if !early {
					cache.clear()
				}
				before := time.Now()
				session, e = p.getSessionContext(ctx, session)
				if e != nil {
					t.Fatal(e)
				}
				r.ReconnectMS = append(r.ReconnectMS, float64(time.Since(before))/float64(time.Millisecond))
				until := time.Now().Add(3500 * time.Millisecond)
				var workers sync.WaitGroup
				errs := make(chan error, 4)
				for worker := range 4 {
					workers.Go(func() {
						c, e := b.DialTCPStream(ctx, remote, netip.AddrPortFrom(tcpTestAddress(remote), 8080))
						if e != nil {
							errs <- e
							return
						}
						defer c.Close()
						payload := bytes.Repeat([]byte{byte(epoch + 1), byte(worker + 1)}, 16<<10)
						got := make([]byte, len(payload))
						for time.Now().Before(until) {
							c.SetDeadline(time.Now().Add(6 * time.Second))
							if _, e = c.Write(payload); e != nil {
								errs <- e
								return
							}
							if _, e = io.ReadFull(c, got); e != nil {
								errs <- e
								return
							}
							if !bytes.Equal(payload, got) {
								errs <- fmt.Errorf("TCP payload corruption")
								return
							}
							tcpBytes.Add(int64(len(payload)))
						}
					})
				}
				workers.Wait()
				close(errs)
				for e := range errs {
					t.Error(e)
				}
				waitTicket(t, cache)
			}
			close(stopSend)
			<-sendDone
			r.DurationSeconds = time.Since(started).Seconds()
			select {
			case e := <-sendErrors:
				t.Fatal(e)
			default:
			}
			time.Sleep(400 * time.Millisecond)
			pair.backends[1].Bind().Close()
			<-readDone
			receiveMu.Lock()
			defer receiveMu.Unlock()
			seen := make(map[int]bool)
			var latencies []time.Duration
			highest := -1
			for _, o := range observations {
				if seen[o.sequence] {
					r.Duplicates++
					continue
				}
				seen[o.sequence] = true
				if o.sequence < highest {
					r.Reordered++
				}
				highest = max(highest, o.sequence)
				latencies = append(latencies, o.latency)
			}
			r.Offered = int(offered.Load())
			r.Delivered = len(seen)
			r.Missing = r.Offered - r.Delivered
			r.TCPBytes = tcpBytes.Load()
			r.LinkDrops = links[0].drops.Load() + links[1].drops.Load()
			r.EarlyAccepted = b.counters.ZeroRTTAccepted.Load()
			r.EarlyRejected = b.counters.ZeroRTTRejected.Load()
			slices.Sort(latencies)
			quantile := func(p float64) float64 {
				if len(latencies) == 0 {
					return 0
				}
				return float64(latencies[min(len(latencies)-1, int(float64(len(latencies)-1)*p))]) / float64(time.Millisecond)
			}
			r.P50MS, r.P95MS, r.P99MS, r.MaxMS = quantile(.5), quantile(.95), quantile(.99), quantile(1)
			// Treat missing packets as +infinity. JSON null means an infinite
			// unconditional percentile, never a sample silently removed.
			rank := (99*r.Offered+99)/100 - 1
			if rank >= 0 && rank < len(latencies) {
				value := float64(latencies[rank]) / float64(time.Millisecond)
				r.UnconditionalP99MS = &value
			}
			results = append(results, r)
			data, _ := json.Marshal(r)
			t.Log(string(data))
			if r.Delivered == 0 || r.Duplicates != 0 || r.TCPBytes == 0 {
				t.Fatal("mixed traffic delivery contract failed")
			}
			// Missing packets count against the latency SLO; do not report only the
			// successful survivors as evidence of healthy UDP application experience.
			if r.UnconditionalP99MS == nil || *r.UnconditionalP99MS > 150 {
				t.Fatal("UDP exceeded controlled-load acceptance: 150ms unconditional p99, missing packets count as infinity")
			}
			if early && r.EarlyAccepted != 3 {
				t.Fatalf("expected three real early reconnects, got %d", r.EarlyAccepted)
			}
		})
	}
	if len(results) == 2 {
		a, b := results[0], results[1]
		if (a.UnconditionalP99MS != nil && b.UnconditionalP99MS != nil && *b.UnconditionalP99MS > *a.UnconditionalP99MS+25) || float64(b.Missing)/float64(b.Offered) > float64(a.Missing)/float64(a.Offered)+.01 {
			t.Error("0-RTT UDP regression exceeds 25ms p99 / 1 percentage point missing")
		}
		if b.Reordered > a.Reordered+2 {
			t.Error("early handover added more than two reordered UDP packets on the FIFO test link")
		}
		if path := os.Getenv("TS_H3_MIXED_RESULT"); path != "" {
			data, _ := json.MarshalIndent(results, "", "  ")
			if e := os.WriteFile(path, append(data, '\n'), 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
}
