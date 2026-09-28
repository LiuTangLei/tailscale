// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

// sendQueuedIPBatch preserves the actor's generation ownership and budget while
// collecting only packets already queued. It never sleeps to form a batch.
func (p *peer) sendQueuedIPBatch(first *packetBuffer) {
	p.connectingPacket.Store(true)
	defer p.connectingPacket.Store(false)
	var owned [32]*packetBuffer
	owned[0] = first
	count := 1
collect:
	for count < len(owned) {
		select {
		case packet := <-p.tx:
			owned[count] = packet
			count++
		default:
			break collect
		}
	}
	defer func() {
		for _, packet := range owned[:count] {
			p.g.txBytes.Add(-int64(len(packet.data)))
			releasePacket(packet)
		}
	}()
	var buffers [32][]byte
	n := 0
	for _, packet := range owned[:count] {
		if !p.stampValid(packet.stamp) {
			p.g.b.counters.SendQueueDrops.Add(1)
			continue
		}
		buffers[n] = packet.data
		n++
	}
	if n == 0 {
		return
	}
	s, err := p.getSession()
	if err != nil {
		if p.g.ctx.Err() == nil {
			p.g.b.counters.SendErrors.Add(uint64(n))
		}
		return
	}
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	// Opening a session can overlap revocation/re-add. Revalidate OLD queued
	// stamps, not merely the new session's authorization, before sending bytes.
	n = 0
	for _, packet := range owned[:count] {
		if !p.stampValid(packet.stamp) {
			continue
		}
		buffers[n] = packet.data
		n++
	}
	if n == 0 {
		return
	}
	handled, err := p.sendIPBatch(s, buffers[:n], 0)
	if !handled {
		for _, packet := range buffers[:n] {
			if err = p.sendPacket(s, packet, p.scratch[:]); err != nil {
				break
			}
		}
	}
	if err != nil && p.g.ctx.Err() == nil {
		p.g.b.counters.SendErrors.Add(1)
	}
}
