// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

type repairTestWire struct {
	frames [][]byte
	busy   bool
	limit  int
}

func (w *repairTestWire) SendDatagram(b []byte) error {
	if w.limit > 0 && len(b) > w.limit {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(w.limit)}
	}
	w.frames = append(w.frames, bytes.Clone(b))
	return nil
}
func (w *repairTestWire) ReceiveDatagram(context.Context) ([]byte, error) { panic("unused") }
func (w *repairTestWire) TrySendDatagramsWithPrefix(_ []byte, b [][]byte) (bool, error) {
	if w.busy {
		return false, nil
	}
	for _, p := range b {
		w.frames = append(w.frames, bytes.Clone(p))
	}
	return true, nil
}
func newRepairTest(w *repairTestWire) *tcpRepair {
	c := &http3Channel{g: &generation{b: &Backend{}}, stream: w}
	r := &tcpRepair{channel: c, try: w, tx: make(map[repairFlowKey]*repairSendFlow), txIDs: make(map[uint64]*repairSendFlow), rx: make(map[uint64]*repairReceiveFlow), partial: make(map[repairAssemblyKey]*repairAssembly), credit: 512, rateCredit: 512, ackCredit: 512, last: time.Now()}
	c.repair = r
	return r
}
func repairIP(n int) []byte {
	p := make([]byte, 40+n)
	p[0] = 0x45
	p[9] = 6
	p[12] = 10
	p[16] = 11
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[20] = 1
	p[22] = 2
	p[32] = 0x50
	p[33] = 0x18
	for i := range p[40:] {
		p[40+i] = byte(i)
	}
	return p
}
func repairACK(id, largest, bits uint64) []byte {
	b := make([]byte, 49)
	b[0] = frameTCPAck
	binary.BigEndian.PutUint64(b[1:], id)
	binary.BigEndian.PutUint64(b[9:], largest)
	binary.BigEndian.PutUint64(b[17:], bits)
	return b
}

func TestTCPRepairGapTailAndUDP(t *testing.T) {
	w := &repairTestWire{}
	r := newRepairTest(w)
	for range 5 {
		if ok, e := r.send(repairIP(32)); !ok || e != nil {
			t.Fatal(ok, e)
		}
	}
	var f *repairSendFlow
	for _, v := range r.tx {
		f = v
	}
	now := time.Now()
	for _, p := range f.packets {
		p.admitted = now
	}
	// Out-of-order selective ACKs retain a hole; the time guard prevents a
	// three-packet reorder from immediately producing a repair.
	if e := r.receive(repairACK(f.id, 5, 0x17), func([]byte) bool { return true }, now); e != nil {
		t.Fatal(e)
	}
	before := len(w.frames)
	r.tick(now.Add(5*time.Millisecond), 20*time.Millisecond)
	if len(w.frames) != before {
		t.Fatal("reorder caused premature copy")
	}
	w.busy = true
	r.tick(now.Add(30*time.Millisecond), 20*time.Millisecond)
	if len(w.frames) != before {
		t.Fatal("repair waited behind or bypassed foreground data")
	}
	w.busy = false
	r.tick(now.Add(35*time.Millisecond), 20*time.Millisecond)
	if len(w.frames) != before+1 || binary.BigEndian.Uint64(w.frames[before][9:]) != 2 {
		t.Fatal("gap not selectively repaired")
	}
	r.tick(now.Add(100*time.Millisecond), 20*time.Millisecond)
	if len(w.frames) != before+1 {
		t.Fatal("gap copied repeatedly without progress")
	}
	// A lone short tail gets exactly one copy, without marking the original
	// lost or changing its admission clock. Long tails get no timer-only copy.
	w2 := &repairTestWire{}
	r2 := newRepairTest(w2)
	r2.send(repairIP(64))
	r2.tick(time.Now().Add(50*time.Millisecond), 20*time.Millisecond)
	r2.tick(time.Now().Add(100*time.Millisecond), 20*time.Millisecond)
	if len(w2.frames) != 2 || r2.channel.g.b.counters.TCPRepairTailProbes.Load() != 1 {
		t.Fatal("short tail probe not single-use")
	}
	w3 := &repairTestWire{}
	r3 := newRepairTest(w3)
	r3.send(repairIP(256))
	r3.tick(time.Now().Add(time.Second), 20*time.Millisecond)
	if len(w3.frames) != 1 {
		t.Fatal("large tail copied")
	}
	udp := repairIP(20)
	udp[9] = 17
	if ok, e := r.send(udp); ok || e != nil {
		t.Fatal("UDP entered repair")
	}
	ack := repairIP(0)
	if ok, _ := r.send(ack); ok {
		t.Fatal("pure TCP ACK entered repair")
	}
	r.tick(now.Add(3*time.Second), 20*time.Millisecond)
	if r.pending != 0 || r.bytes != 0 {
		t.Fatal("cache did not expire")
	}
}

func TestTCPRepairReassemblyDedupAndQueueAdmission(t *testing.T) {
	w := &repairTestWire{limit: 1100}
	r := newRepairTest(w)
	packet := repairIP(1400)
	if ok, e := r.send(packet); !ok || e != nil || len(w.frames) != 2 {
		t.Fatal(ok, e, len(w.frames))
	}
	rx := newRepairTest(&repairTestWire{})
	delivered := 0
	accept := false
	deliver := func(got []byte) bool {
		if !bytes.Equal(got, packet) {
			t.Fatal("packet changed")
		}
		if accept {
			delivered++
		}
		return accept
	}
	now := time.Now()
	for _, b := range w.frames {
		if e := rx.receive(b, deliver, now); e != nil {
			t.Fatal(e)
		}
	}
	if len(rx.rx) != 0 {
		t.Fatal("ACKed a local queue drop")
	}
	accept = true
	for i := len(w.frames) - 1; i >= 0; i-- {
		if e := rx.receive(w.frames[i], deliver, now); e != nil {
			t.Fatal(e)
		}
	}
	for _, b := range w.frames {
		if e := rx.receive(b, deliver, now); e != nil {
			t.Fatal(e)
		}
	}
	if delivered != 1 {
		t.Fatalf("delivered %d copies", delivered)
	}
	rx.tick(now.Add(20*time.Millisecond), time.Millisecond)
	ackWire := rx.try.(*repairTestWire)
	if len(ackWire.frames) != 1 {
		t.Fatal("missing coalesced ACK")
	}
	r.receive(ackWire.frames[0], nil, now.Add(20*time.Millisecond))
	if r.pending != 0 {
		t.Fatal("ACK did not release cached packet")
	}
	// Private repair contexts cannot be used to make UDP reliable.
	bad := bytes.Clone(packet)
	bad[9] = 17
	if e := rx.receive(repairFrames(2, 1, bad, 2000)[0], deliver, now); e == nil {
		t.Fatal("UDP in repair context accepted")
	}
}

func TestTCPRepairBoundsAndReceiveWindow(t *testing.T) {
	w := &repairTestWire{}
	r := newRepairTest(w)
	for range repairMaxPending + 10 {
		r.send(repairIP(1000))
	}
	if r.pending > repairMaxPending || r.bytes > repairCacheBytes {
		t.Fatal("unbounded retransmit cache")
	}
	f := &repairReceiveFlow{}
	f.mark(1)
	f.mark(260)
	f.mark(258)
	if !f.seen(1) || !f.seen(260) || !f.seen(258) || f.seen(259) {
		t.Fatal("dedup window incorrect")
	}
	for seq := uint64(261); seq < 600; seq++ {
		f.mark(seq)
	}
	if !f.seen(258) || !f.seen(599) {
		t.Fatal("late duplicate escaped receive window")
	}
}

func TestTCPRepairNegotiationResumptionAndLegacyPeer(t *testing.T) {
	for _, flags := range [][2]bool{{true, true}, {true, false}, {false, true}} {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			index := 0
			pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.TCPRepair = flags[index]; index++ })
			fns := pair.open(t)
			remote := pair.keys[1].Public().Raw32()
			p, e := pair.backends[0].active.Load().peer(remote, nil)
			if e != nil {
				t.Fatal(e)
			}
			s, e := p.getSession()
			if e != nil {
				t.Fatal(e)
			}
			want := flags[0] && flags[1]
			if got := s.dgram.(*http3Channel).repair != nil; got != want {
				t.Fatal("full handshake repair", got, want)
			}
			endpoint, e := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
			if e != nil {
				t.Fatal(e)
			}
			send := func(packet []byte) {
				t.Helper()
				if e := pair.backends[0].Bind().Send([][]byte{packet}, endpoint, 0); e != nil {
					t.Fatal(e)
				}
				if got := readOne(t, fns[1]); !bytes.Equal(got, packet) {
					t.Fatal("IP packet changed")
				}
			}
			send(repairIP(1400))
			waitTicket(t, pair.backends[0].clientSessionCache(remote))
			old := s
			p.closeSession("repair test reconnect")
			s, e = p.getSession()
			if e != nil {
				t.Fatal(e)
			}
			if s == old || !s.q.ConnectionState().Used0RTT {
				t.Fatal("did not exercise real resumed tunnel")
			}
			if got := s.dgram.(*http3Channel).repair != nil; got != want {
				t.Fatal("resumed negotiation mismatch")
			}
			send(repairIP(64))
			udp := repairIP(32)
			udp[9] = 17
			send(udp)
		})
	}
}

func TestTCPRepairReceiveWindowShifts(t *testing.T) {
	for _, shift := range []uint64{1, 2, 63, 64, 65, 127, 128, 129, 255, 256, 1000} {
		f := &repairReceiveFlow{}
		seen := map[uint64]bool{}
		for _, seq := range []uint64{1, 4, 63, 64, 120, 200, 255} {
			f.mark(seq)
			seen[seq] = true
		}
		last := uint64(255) + shift
		f.mark(last)
		seen[last] = true
		for seq := uint64(1); seq <= last; seq++ {
			want := last-seq >= 256 || seen[seq]
			if f.seen(seq) != want {
				t.Fatalf("shift %d seq %d", shift, seq)
			}
		}
	}
}

func TestTCPRepairActualH3GapDoesNotHoldUDP(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.TCPRepair = true })
	fns := pair.open(t)
	remote := pair.keys[1].Public().Raw32()
	p, e := pair.backends[0].active.Load().peer(remote, nil)
	if e != nil {
		t.Fatal(e)
	}
	s, e := p.getSession()
	if e != nil {
		t.Fatal(e)
	}
	c := s.dgram.(*http3Channel)
	// Inject a deliberate sequence hole through real authenticated H3 frames.
	// Neither the later TCP packet nor raw UDP may wait for missing sequence 1.
	later := repairIP(64)
	later[40] = 2
	if e := c.stream.SendDatagram(repairFrames(100, 2, later, 1000)[0]); e != nil {
		t.Fatal(e)
	}
	udp := repairIP(64)
	udp[9] = 17
	udp[40] = 9
	if e := c.SendDatagram(append([]byte{frameRaw}, udp...)); e != nil {
		t.Fatal(e)
	}
	first, second := readOne(t, fns[1]), readOne(t, fns[1])
	if !(bytes.Equal(first, later) && bytes.Equal(second, udp) || bytes.Equal(first, udp) && bytes.Equal(second, later)) {
		t.Fatal("gap changed or held subsequent IP packets")
	}
	missing := repairIP(64)
	missing[40] = 1
	if e := c.stream.SendDatagram(repairFrames(100, 1, missing, 1000)[0]); e != nil {
		t.Fatal(e)
	}
	if got := readOne(t, fns[1]); !bytes.Equal(got, missing) {
		t.Fatal("late hole was not immediately delivered")
	}
	if e := c.stream.SendDatagram(repairFrames(100, 2, later, 1000)[0]); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for pair.backends[1].counters.TCPRepairDuplicates.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if pair.backends[1].counters.TCPRepairDuplicates.Load() != 1 {
		t.Fatal("actual H3 duplicate escaped suppression")
	}
	if pair.backends[1].counters.ReceivedPackets.Load() != 3 {
		t.Fatal("carrier duplicate reached IP queue")
	}
}

type repairAdmissionWire struct {
	*repairTestWire
	entered, release chan struct{}
}

func (w *repairAdmissionWire) SendDatagram(b []byte) error {
	e := w.repairTestWire.SendDatagram(b)
	close(w.entered)
	<-w.release
	return e
}
func TestTCPRepairClockStartsAfterAdmission(t *testing.T) {
	w := &repairAdmissionWire{repairTestWire: &repairTestWire{}, entered: make(chan struct{}), release: make(chan struct{})}
	r := newRepairTest(w.repairTestWire)
	r.channel.stream = w
	done := make(chan error, 1)
	go func() { _, e := r.send(repairIP(32)); done <- e }()
	<-w.entered
	r.tick(time.Now().Add(time.Second), time.Millisecond)
	if len(w.frames) != 1 {
		t.Fatal("local admission wait caused tail probe")
	}
	released := time.Now()
	close(w.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	for _, f := range r.tx {
		for _, p := range f.packets {
			if p.admitted.Before(released) {
				t.Fatal("clock includes local queue wait")
			}
		}
	}
}

func TestTCPRepairClassificationAndNegotiatedContexts(t *testing.T) {
	v6 := make([]byte, 60+64)
	v6[0] = 0x60
	v6[6] = 6
	binary.BigEndian.PutUint16(v6[4:6], uint16(len(v6)-40))
	v6[8] = 1
	v6[24] = 2
	v6[40] = 1
	v6[42] = 2
	v6[52] = 0x50
	v6[53] = 0x18
	if _, short, ok := repairTCP(v6); !ok || !short {
		t.Fatal("IPv6 TCP not classified")
	}
	for _, next := range []byte{0, 17, 44, 60} {
		p := bytes.Clone(v6)
		p[6] = next
		if _, _, ok := repairTCP(p); ok {
			t.Fatal("IPv6 UDP/extension/fragment entered repair")
		}
	}
	for _, fragment := range []uint16{1, 0x2000} {
		p := repairIP(64)
		binary.BigEndian.PutUint16(p[6:8], fragment)
		if _, _, ok := repairTCP(p); ok {
			t.Fatal("IPv4 fragment entered repair")
		}
	}
	p := repairIP(64)
	binary.BigEndian.PutUint16(p[6:8], 0x4000)
	if _, _, ok := repairTCP(p); !ok {
		t.Fatal("DF flag rejected complete TCP")
	}
	c := &http3Channel{g: &generation{b: &Backend{}}}
	for _, kind := range []byte{frameTCPRepair, frameTCPAck} {
		b := append([]byte{kind}, make([]byte, 64)...)
		if c.normalize(b) != nil {
			t.Fatal("unnegotiated private context accepted")
		}
		c.repair = &tcpRepair{}
		if got := c.normalize(b); len(got) == 0 || got[0] != kind {
			t.Fatal("negotiated context lost")
		}
		c.repair = nil
	}
}
