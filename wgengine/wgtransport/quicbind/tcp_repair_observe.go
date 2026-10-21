// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import "encoding/binary"

// TCP acknowledgments are advisory cancellation of supplemental copies, not
// authorization or a substitute for the IP engine's live source/ACL checks.
func (r *tcpRepair) observeTCPLocked(packet []byte) {
	key, off, _, ok := repairTCPInfo(packet)
	if !ok || packet[off+13]&0x10 == 0 {
		return
	}
	var reverse repairFlowKey
	reverse[0] = key[0]
	copy(reverse[1:17], key[17:33])
	copy(reverse[17:33], key[1:17])
	copy(reverse[33:35], key[35:37])
	copy(reverse[35:37], key[33:35])
	f := r.tx[reverse]
	if f == nil {
		return
	}
	ack := binary.BigEndian.Uint32(packet[off+8:])
	for _, p := range f.packets {
		if int32(p.tcpEnd-ack) <= 0 {
			r.remove(f, p)
		}
	}
}

// Raw TCP ACKs use the direct QUIC receive callback. Never wait on the repair
// lock from that event loop; a missed observation only leaves a bounded copy.
func (r *tcpRepair) observeTCP(packet []byte) {
	if len(packet) < 20 {
		return
	}
	if packet[0]>>4 == 4 && packet[9] != 6 {
		return
	}
	if packet[0]>>4 == 6 && (len(packet) < 40 || packet[6] != 6) {
		return
	}
	if !r.mu.TryLock() {
		return
	}
	defer r.mu.Unlock()
	r.observeTCPLocked(packet)
}

func (p *peer) observeTCP(s *session, packet []byte) {
	if c, ok := s.dgram.(*http3Channel); ok && c.repair != nil {
		c.repair.observeTCP(packet)
	}
}
