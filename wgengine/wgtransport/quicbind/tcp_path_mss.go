// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

// A magicsock PacketConn cannot advertise DF, so quic-go cannot grow its
// packet size with DPLPMTUD. Keep the safe 1200-byte Initial and negotiate TCP
// segments that fit that fixed datagram path instead of fragmenting every
// full-size TUN packet. This changes neither the interface MTU nor UDP/IPv6
// fragmentation support, and does not pretend that magicsock supports DF/GSO.
//
// 64 bytes covers a maximum short QUIC header (1+20+4), a 16-byte AEAD tag,
// DATAGRAM type/length (1+8), HTTP quarter-stream ID (8), and IP context ID (1).
const h3TCPDatagramHeadroom = 64

func (c Config) tcpMSSLimit(ipVersion byte) uint16 {
	limit := c.TCPMSS
	if !c.HTTP3 || c.IO != "magicsock" || c.TCPStreams {
		return limit
	}
	size := c.InitialPacketSize
	if size == 0 {
		size = 1200 // same as NewFactory's default
	}
	header := uint16(40) // fixed IPv4 and TCP headers; TCP accounts for options
	switch ipVersion {
	case 4:
	case 6:
		header = 60
	default:
		return 0
	}
	if size <= h3TCPDatagramHeadroom+header {
		return limit
	}
	pathLimit := size - h3TCPDatagramHeadroom - header
	if limit == 0 || pathLimit < limit {
		return pathLimit
	}
	return limit
}

// isTCPSYN is only a cheap gate for retaining the steady-state batch fast path.
// clampTCPMSS performs the complete length/options/fragmentation validation on
// a private scratch copy before any byte is modified.
func isTCPSYN(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	var offset int
	switch packet[0] >> 4 {
	case 4:
		offset = int(packet[0]&15) * 4
		if offset < 20 || packet[9] != 6 {
			return false
		}
	case 6:
		offset = 40
		if packet[6] != 6 { // do not rewrite IPv6 extension/fragment headers
			return false
		}
	default:
		return false
	}
	return len(packet) >= offset+20 && packet[offset+13]&2 != 0
}

func (p *peer) clampPacketTCPMSS(packet []byte) {
	if !isTCPSYN(packet) {
		return
	}
	if clampTCPMSS(packet, p.g.b.factory.cfg.tcpMSSLimit(packet[0]>>4)) {
		p.g.b.counters.TCPMSSClamps.Add(1)
	}
}
