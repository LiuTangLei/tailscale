// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/LiuTangLei/wireguard-go/conn"
	"net"
	"testing"
	"time"
)

func fragment(id uint32, total, off int, data []byte) []byte {
	f := make([]byte, fragmentHeader+len(data))
	f[0] = frameFragment
	binary.BigEndian.PutUint32(f[1:5], id)
	binary.BigEndian.PutUint16(f[5:7], uint16(total))
	binary.BigEndian.PutUint16(f[7:9], uint16(off))
	copy(f[9:], data)
	return f
}
func TestFragmentsBoundedAndOutOfOrder(t *testing.T) {
	var r reassembler
	now := time.Now()
	first := fragment(1, 6, 0, []byte("abc"))
	last := fragment(1, 6, 3, []byte("def"))
	if p, e := r.consume(last, now); e != nil || p != nil {
		t.Fatalf("partial %q %v", p, e)
	}
	if p, e := r.consume(first, now); e != nil || !bytes.Equal(p, []byte("abcdef")) {
		t.Fatalf("assembled %q %v", p, e)
	}
	r.consume(first, now)
	if _, e := r.consume(fragment(1, 6, 1, []byte("xx")), now); e == nil {
		t.Fatal("accepted overlap")
	}
	for i := 0; i < maxAssemblies; i++ {
		if _, e := r.consume(fragment(uint32(i+10), 6, 0, []byte("abc")), now); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := r.consume(fragment(100, 6, 0, []byte("abc")), now); e == nil {
		t.Fatal("unbounded assemblies")
	}
	if _, e := r.consume(fragment(101, 6, 0, []byte("abc")), now.Add(3*time.Second)); e != nil {
		t.Fatal("expired assemblies not released", e)
	}
	for _, f := range [][]byte{nil, {9, 1}, {frameFragment, 1}, fragment(99, 4, 3, []byte("bad"))} {
		if _, e := r.consume(f, now); e == nil {
			t.Fatalf("accepted malformed frame %x", f)
		}
	}
}
func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 1})
	f.Add(fragment(1, 5, 0, []byte("12")))
	f.Fuzz(func(t *testing.T, b []byte) {
		var r reassembler
		out, _ := r.consume(b, time.Unix(0, 0))
		if len(out) > maxPacket {
			t.Fatal("oversized result")
		}
	})
}

func TestSingleSidedRebindReconnect(t *testing.T) {
	for _, mode := range []string{"udp", "magicsock"} {
		t.Run(mode, func(t *testing.T) {
			p := newTestPair(t, mode)
			fns := p.open(t)
			for round := range 4 {
				if round > 0 {
					p.backends[round%2].NetworkChanged(true, true)
				}
				for i := range 2 {
					pk := p.keys[i^1].Public().Raw32()
					ep, e := p.backends[i].Bind().ParseEndpoint(hex.EncodeToString(pk[:]))
					if e != nil {
						t.Fatal(e)
					}
					data := bytes.Repeat([]byte{byte(round + 3)}, 512)
					// A datagram racing the peer's CONNECTION_CLOSE may legitimately
					// be lost. Retry like an upper-layer probe; do not require QUIC
					// DATAGRAM to provide reliability that UDP itself doesn't offer.
					delivered := make(chan error, 1)
					go func() {
						buf := make([]byte, maxPacket)
						sizes := make([]int, 1)
						eps := make([]conn.Endpoint, 1)
						for {
							_, err := fns[i^1]([][]byte{buf}, sizes, eps)
							if err != nil {
								delivered <- err
								return
							}
							if bytes.Equal(buf[:sizes[0]], data) {
								delivered <- nil
								return
							}
						}
					}()
					deadline := time.NewTimer(5 * time.Second)
					ticker := time.NewTicker(20 * time.Millisecond)
					if e := p.backends[i].Bind().Send([][]byte{data}, ep, 0); e != nil {
						t.Fatal(e)
					}
				wait:
					for {
						select {
						case err := <-delivered:
							if err != nil {
								t.Fatal(err)
							}
							break wait
						case <-ticker.C:
							_ = p.backends[i].Bind().Send([][]byte{data}, ep, 0)
						case <-deadline.C:
							t.Fatal("rebind did not recover within 5s")
						}
					}
					ticker.Stop()
					deadline.Stop()
				}
			}
		})
	}
}

func TestUntrustedCertificateFailsActualHandshake(t *testing.T) {
	p := newTestPair(t, "udp")
	// Corrupt only the client's trust map, leaving valid TLS identities on both
	// ends. A real TLS handshake must reject even though WG public keys match.
	p.backends[0].factory.byPin = map[[32]byte][32]byte{}
	p.open(t)
	g := p.backends[0].active.Load()
	pk := p.keys[1].Public().Raw32()
	peer, e := g.peer(pk, nil)
	if e != nil {
		t.Fatal(e)
	}
	s, e := peer.getSession()
	if e == nil || s != nil {
		t.Fatal("accepted untrusted TLS certificate")
	}
	if p.backends[0].counters.Connections.Load() != 0 {
		t.Fatal("untrusted connection installed")
	}
}

func TestCloseUnblocksReceiveAndSend(t *testing.T) {
	p := newTestPair(t, "udp")
	fns := p.open(t)
	done := make(chan error, 1)
	go func() {
		_, e := fns[0]([][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1))
		done <- e
	}()
	if e := p.backends[0].Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatalf("receive=%v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("receive did not unblock")
	}
	if _, _, e := p.backends[0].Bind().Open(0); !errors.Is(e, net.ErrClosed) {
		t.Fatal("final close allowed reopen", e)
	}
}

func BenchmarkRawFrame(b *testing.B) {
	f := append([]byte{frameRaw}, make([]byte, 1280)...)
	var r reassembler
	now := time.Now()
	b.SetBytes(1280)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		r.consume(f, now)
	}
}
func BenchmarkPacketBuffer(b *testing.B) {
	data := make([]byte, 1280)
	b.SetBytes(1280)
	b.ReportAllocs()
	for range b.N {
		p := acquirePacket(data)
		releasePacket(p)
	}
}
