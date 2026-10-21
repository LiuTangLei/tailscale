// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	tcpRepairHeader       = "Connect-IP-TCP-Repair"
	tcpRepairVersion      = "v2"
	frameTCPRepair   byte = 3
	frameTCPAck      byte = 4
	repairHeader          = 21 // context, directional flow ID, packet sequence, total, offset
	repairMaxPacket       = 2048
	repairMaxFlows        = 256
	repairMaxPending      = 256
	repairCacheBytes      = 256 << 10
	repairLifetime        = 2 * time.Second
)

type repairFlowKey [37]byte

// Only complete, unfragmented TCP packets with data, SYN or FIN are eligible.
// ACK-only packets, UDP, IP fragments and unsupported extension headers retain
// the immediate raw DATAGRAM path. The inner TCP stack remains authoritative.
func repairTCP(packet []byte) (key repairFlowKey, short bool, ok bool) {
	if len(packet) > repairMaxPacket {
		return
	}
	key, _, n, valid := repairTCPInfo(packet)
	return key, n <= 128, valid && n > 0
}

func repairTCPInfo(packet []byte) (key repairFlowKey, off, sequenceBytes int, ok bool) {
	if len(packet) < 40 || len(packet) > maxPacket {
		return
	}
	switch packet[0] >> 4 {
	case 4:
		off = int(packet[0]&15) * 4
		if off < 20 || len(packet) < off+20 || packet[9] != 6 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return
		}
		key[0] = 4
		copy(key[1:5], packet[12:16])
		copy(key[17:21], packet[16:20])
	case 6:
		off = 40
		if len(packet) < 60 || packet[6] != 6 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return
		}
		key[0] = 6
		copy(key[1:17], packet[8:24])
		copy(key[17:33], packet[24:40])
	default:
		return
	}
	h := int(packet[off+12]>>4) * 4
	if h < 20 || off+h > len(packet) {
		return
	}
	n := len(packet) - off - h
	if packet[off+13]&2 != 0 {
		n++
	}
	if packet[off+13]&1 != 0 {
		n++
	}
	copy(key[33:], packet[off:off+4])
	return key, off, n, true
}

type opportunisticDatagrams interface {
	TrySendDatagramsWithPrefix([]byte, [][]byte) (bool, error)
}

type repairPacket struct {
	seq              uint64
	frames           [][]byte
	size             int
	tcpStart, tcpEnd uint32
	admitted         time.Time
	short, copied    bool
}
type repairSendFlow struct {
	id, next, largest uint64
	duplicateAck      uint64
	tcpNext           uint32
	tcpStarted        bool
	packets           map[uint64]*repairPacket
}
type repairReceiveFlow struct {
	largest     uint64
	duplicates  uint64
	ackAt       time.Time
	urgentUntil uint64
	bits        [4]uint64
	dirty       bool
	key         repairFlowKey
}
type repairAssemblyKey struct{ flow, seq uint64 }
type repairAssembly struct {
	assembly
	total int
}
type tcpRepair struct {
	mu             sync.Mutex
	channel        *http3Channel
	try            opportunisticDatagrams
	prefix         []byte
	tx             map[repairFlowKey]*repairSendFlow
	txIDs          map[uint64]*repairSendFlow
	rx             map[uint64]*repairReceiveFlow
	partial        map[repairAssemblyKey]*repairAssembly
	next           uint64
	bytes, pending int
	credit         int // at most 5% of admitted TCP bytes plus one 512-byte initial burst
	rateCredit     int // a second, absolute 16 KiB/s repair ceiling
	ackCredit      int // independent 8 KiB/s coalesced control ceiling
	last           time.Time
	ackRTT         time.Duration
	reorderSlack   uint8 // grows to 2 RTTs after redundant copies are observed
}

func supportsTCPRepair(q *quic.Conn) bool { _, ok := any(q).(opportunisticDatagrams); return ok }

func (c *http3Channel) enableTCPRepair(enabled bool) {
	if !enabled {
		return
	}
	sender, ok := any(c.q).(opportunisticDatagrams)
	stream, identified := c.stream.(interface{ StreamID() quic.StreamID })
	if !ok || !identified || stream.StreamID() < 0 || stream.StreamID()%4 != 0 {
		return
	}
	c.repair = &tcpRepair{
		channel: c, try: sender,
		prefix:  quicvarint.Append(nil, uint64(stream.StreamID())/4),
		tx:      make(map[repairFlowKey]*repairSendFlow),
		txIDs:   make(map[uint64]*repairSendFlow),
		rx:      make(map[uint64]*repairReceiveFlow),
		partial: make(map[repairAssemblyKey]*repairAssembly),
		credit:  512, rateCredit: 512, ackCredit: 512, last: time.Now(),
	}
}

func repairFrames(flow, seq uint64, packet []byte, chunk int) [][]byte {
	frames := make([][]byte, 0, (len(packet)+chunk-1)/chunk)
	for off := 0; off < len(packet); off += chunk {
		n := min(chunk, len(packet)-off)
		b := make([]byte, repairHeader+n)
		b[0] = frameTCPRepair
		binary.BigEndian.PutUint64(b[1:9], flow)
		binary.BigEndian.PutUint64(b[9:17], seq)
		binary.BigEndian.PutUint16(b[17:19], uint16(len(packet)))
		binary.BigEndian.PutUint16(b[19:21], uint16(off))
		copy(b[repairHeader:], packet[off:off+n])
		frames = append(frames, b)
	}
	return frames
}

// send is called under the existing peer send lock. Admission clocks start
// after QUIC has accepted the entire original, never while waiting locally.
func (r *tcpRepair) send(packet []byte) (bool, error) {
	key, off, sequenceBytes, ok := repairTCPInfo(packet)
	if !ok || sequenceBytes == 0 || len(packet) > repairMaxPacket {
		return false, nil
	}
	r.mu.Lock()
	f := r.tx[key]
	if f == nil {
		if len(r.tx) >= repairMaxFlows {
			r.mu.Unlock()
			return false, nil
		}
		r.next++
		f = &repairSendFlow{id: r.next, packets: make(map[uint64]*repairPacket)}
		r.tx[key] = f
		r.txIDs[f.id] = f
	}
	start := binary.BigEndian.Uint32(packet[off+4:])
	end := start + uint32(sequenceBytes)
	if packet[off+13]&2 != 0 && (!f.tcpStarted || end != f.tcpNext) {
		// A new TCP incarnation can reuse a four-tuple on this QUIC session.
		for _, old := range f.packets {
			r.remove(f, old)
		}
	} else if f.tcpStarted && int32(start-f.tcpNext) < 0 {
		// The inner TCP stack has already retransmitted this sequence space.
		// Cancel its supplemental copy and send this packet on the raw path.
		for _, old := range f.packets {
			if int32(old.tcpStart-start) >= 0 && int32(end-old.tcpEnd) >= 0 {
				r.remove(f, old)
			}
		}
		r.mu.Unlock()
		return false, nil
	}
	f.tcpStarted = true
	f.tcpNext = end
	if r.pending >= repairMaxPending || r.bytes+len(packet) > repairCacheBytes || f.next >= quicvarint.Max {
		r.mu.Unlock()
		return false, nil
	}
	f.next++
	p := &repairPacket{seq: f.next, size: len(packet), short: sequenceBytes <= 128, tcpStart: start, tcpEnd: end}
	f.packets[p.seq] = p
	r.pending++
	r.bytes += len(packet)
	r.mu.Unlock()
	p.frames = repairFrames(f.id, p.seq, packet, len(packet))
	err := r.channel.stream.SendDatagram(p.frames[0])
	var large *quic.DatagramTooLargeError
	if errors.As(err, &large) {
		// Reserve the maximum H3 stream prefix, even on implementations reporting
		// the pre-prefix limit. Both initial and repair copies use identical pieces.
		chunk := int(large.MaxDatagramPayloadSize) - 8 - repairHeader
		if chunk > 0 {
			p.frames = repairFrames(f.id, p.seq, packet, chunk)
			err = nil
			for _, b := range p.frames {
				if err = r.channel.stream.SendDatagram(b); err != nil {
					break
				}
			}
		}
	}
	r.mu.Lock()
	if err == nil {
		r.channel.g.b.counters.TCPRepairOriginalBytes.Add(uint64(len(packet)))
	}
	if f.packets[p.seq] == p {
		if err != nil {
			r.remove(f, p)
		} else {
			p.admitted = time.Now()
			r.credit = min(16<<10, r.credit+len(packet)/20)
		}
	}
	r.mu.Unlock()
	return true, err
}
func (r *tcpRepair) remove(f *repairSendFlow, p *repairPacket) {
	delete(f.packets, p.seq)
	r.pending--
	r.bytes -= p.size
}

func (f *repairReceiveFlow) seen(seq uint64) bool {
	if seq > f.largest {
		return false
	}
	d := f.largest - seq
	return d >= 256 || f.bits[d/64]&(uint64(1)<<(d%64)) != 0
}
func (f *repairReceiveFlow) mark(seq uint64) {
	if seq > f.largest {
		shift := seq - f.largest
		var next [4]uint64
		if shift < 256 {
			words, bits := int(shift/64), uint(shift%64)
			for dst := 3; dst >= words; dst-- {
				src := dst - words
				next[dst] = f.bits[src] << bits
				if bits != 0 && src > 0 {
					next[dst] |= f.bits[src-1] >> (64 - bits)
				}
			}
		}
		f.bits = next
		f.largest = seq
	}
	d := f.largest - seq
	if d < 256 {
		f.bits[d/64] |= uint64(1) << (d % 64)
	}
	f.dirty = true
}

// receive acknowledges only complete TCP packets accepted by the existing IP
// queue. It delivers each packet immediately: gaps never hold another packet.
func (r *tcpRepair) receive(b []byte, deliver func([]byte) bool, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b[0] == frameTCPAck {
		ack, err := parseRepairACK(b)
		if err != nil {
			return err
		}
		f := r.txIDs[ack.id]
		if f == nil || ack.largest > f.next {
			return nil
		}
		if ack.duplicates > f.duplicateAck {
			f.duplicateAck = ack.duplicates
			r.reorderSlack = min(3, r.reorderSlack+1)
		}
		f.largest = max(f.largest, ack.largest)
		var latest time.Time
		for seq, p := range f.packets {
			if seq > ack.largest {
				continue
			}
			d := ack.largest - seq
			if d >= 256 {
				// The receiver cannot distinguish this packet from an old
				// duplicate anymore. Leave recovery to the inner TCP stack.
				r.remove(f, p)
				continue
			}
			if ack.bits[d/64]&(uint64(1)<<(d%64)) == 0 {
				continue
			}
			if !p.copied && p.admitted.After(latest) {
				latest = p.admitted
			}
			r.remove(f, p)
		}
		// One RTT sample per ACK, from the newest un-retransmitted packet.
		if !latest.IsZero() {
			sample := now.Sub(latest)
			if r.ackRTT == 0 {
				r.ackRTT = sample
			} else {
				r.ackRTT = (7*r.ackRTT + sample) / 8
			}
		}
		return nil
	}
	if len(b) <= repairHeader {
		return errors.New("short TCP repair frame")
	}
	id, seq := binary.BigEndian.Uint64(b[1:9]), binary.BigEndian.Uint64(b[9:17])
	total, off := int(binary.BigEndian.Uint16(b[17:19])), int(binary.BigEndian.Uint16(b[19:21]))
	data := b[repairHeader:]
	if id == 0 || id > quicvarint.Max || seq == 0 || seq > quicvarint.Max || total < 40 || total > repairMaxPacket || off+len(data) > total {
		return errors.New("invalid TCP repair bounds")
	}
	f := r.rx[id]
	if f != nil && f.seen(seq) {
		f.dirty = true
		f.ackAt = now
		if f.largest-seq < 256 {
			f.duplicates = min(uint64(quicvarint.Max), f.duplicates+1)
		}
		r.channel.g.b.counters.TCPRepairDuplicates.Add(1)
		return nil
	}
	if f == nil && len(r.rx) >= repairMaxFlows {
		return nil
	}
	var packet []byte
	if off == 0 && len(data) == total {
		packet = data
	} else {
		k := repairAssemblyKey{id, seq}
		for key, a := range r.partial {
			if !now.Before(a.expires) {
				delete(r.partial, key)
			}
		}
		a := r.partial[k]
		if a == nil {
			if len(r.partial) >= maxAssemblies {
				return nil
			}
			a = &repairAssembly{assembly: assembly{data: make([]byte, total), expires: now.Add(repairLifetime)}, total: total}
			r.partial[k] = a
		}
		if total != a.total {
			delete(r.partial, k)
			return errors.New("changed TCP repair total")
		}
		end := off + len(data)
		for _, span := range a.spans[:a.count] {
			if off < span.end && end > span.start {
				if off == span.start && end == span.end {
					return nil
				}
				delete(r.partial, k)
				return errors.New("overlapping TCP repair pieces")
			}
		}
		if a.count == len(a.spans) {
			delete(r.partial, k)
			return errors.New("too many TCP repair pieces")
		}
		copy(a.data[off:], data)
		a.spans[a.count] = byteRange{off, end}
		a.count++
		a.received += len(data)
		if a.received != total {
			return nil
		}
		packet = a.data
		delete(r.partial, k)
	}
	key, short, valid := repairTCP(packet)
	if !valid {
		return errors.New("non TCP repair payload")
	}
	if f != nil && f.key != key {
		return errors.New("TCP repair flow changed")
	}
	r.observeTCPLocked(packet)
	if !deliver(packet) {
		return nil
	}
	if f == nil {
		f = &repairReceiveFlow{key: key}
		r.rx[id] = f
	}
	previous := f.largest
	f.mark(seq)
	if seq > previous+1 {
		f.urgentUntil = max(f.urgentUntil, seq+2)
	}
	due := now.Add(25 * time.Millisecond)
	if short || seq <= f.urgentUntil || seq < previous {
		due = now
	}
	if f.ackAt.IsZero() || due.Before(f.ackAt) {
		f.ackAt = due
	}
	return nil
}

func (r *tcpRepair) tick(now time.Time, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	elapsed := min(now.Sub(r.last), time.Second)
	r.last = now
	r.rateCredit = min(2048, r.rateCredit+int(elapsed*16384/time.Second))
	r.ackCredit = min(512, r.ackCredit+int(elapsed*8192/time.Second))
	// Delay routine ACKs, but promptly report new holes and short tails.
	// Two small ACK frames can share one paced QUIC packet; admission remains
	// atomic and yields to already-queued UDP or original TCP packets.
	dueACK := false
	for _, f := range r.rx {
		if f.dirty && !now.Before(f.ackAt) {
			dueACK = true
			break
		}
	}
	// Keep the idle worker allocation-free. The wire buffers escape through
	// the queue interface, so allocate them only when a due ACK exists.
	if dueACK {
		var storage [2][58]byte
		var payloads [2][]byte
		var selected [2]*repairReceiveFlow
		count, total := 0, 0
		for id, f := range r.rx {
			if !f.dirty || now.Before(f.ackAt) {
				continue
			}
			b := appendRepairACK(storage[count][:0], repairAcknowledgment{id: id, largest: f.largest, duplicates: f.duplicates, bits: f.bits})
			cost := len(b) + len(r.prefix)
			if total+cost > r.ackCredit {
				continue
			}
			selected[count] = f
			payloads[count] = b
			total += cost
			count++
			if count == len(payloads) {
				break
			}
		}
		if count > 0 {
			if ok, _ := r.try.TrySendDatagramsWithPrefix(r.prefix, payloads[:count]); ok {
				for _, f := range selected[:count] {
					f.dirty = false
					f.ackAt = time.Time{}
				}
				r.ackCredit -= total
				r.channel.g.b.counters.TCPRepairControlBytes.Add(uint64(total))
			}
		}
	}
	rtt = max(rtt, r.ackRTT, 5*time.Millisecond)
	for _, f := range r.tx {
		for _, p := range f.packets {
			if p.admitted.IsZero() {
				continue
			}
			age := now.Sub(p.admitted)
			if age >= repairLifetime {
				r.remove(f, p)
				continue
			}
			if p.copied {
				continue
			}
			gap := f.largest >= p.seq+3 && age >= rtt*time.Duration(5+r.reorderSlack)/4
			tail := len(f.packets) == 1 && p.short && age >= rtt*time.Duration(9+2*r.reorderSlack)/8+2*time.Millisecond
			if !gap && !tail {
				continue
			}
			cost := p.size + len(p.frames)*(repairHeader+len(r.prefix))
			if len(p.frames) > 2 || cost > r.credit || cost > r.rateCredit {
				continue
			}
			if ok, _ := r.try.TrySendDatagramsWithPrefix(r.prefix, p.frames); ok {
				p.copied = true
				r.credit -= cost
				r.rateCredit -= cost
				c := &r.channel.g.b.counters
				c.TCPRepairPackets.Add(1)
				c.TCPRepairBytes.Add(uint64(cost))
				if !gap {
					c.TCPRepairTailProbes.Add(1)
				}
			}
			return // at most one copy batch, never a repair burst
		}
	}
}

func (p *peer) startTCPRepair(s *session) {
	c, ok := s.dgram.(*http3Channel)
	if !ok || c.repair == nil {
		return
	}
	p.g.workers.Add(1)
	go func() {
		defer p.g.workers.Done()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-s.q.Context().Done():
				return
			case now := <-ticker.C:
				if !p.stampValid(s.stamp) {
					return
				}
				c.repair.tick(now, s.q.ConnectionStats().SmoothedRTT)
			}
		}
	}()
}
