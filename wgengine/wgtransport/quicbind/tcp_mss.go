package quicbind

import "encoding/binary"

// clampTCPMSS lowers only an existing MSS option on a complete TCP SYN packet.
// It does not lower the IP MTU: IPv6 and large UDP packets retain fragmentation.
// The caller owns packet (the carrier's scratch copy). Fragmented/unsupported
// headers and malformed TCP options are left untouched, not partially rewritten.
func clampTCPMSS(packet []byte, limit uint16) bool {
	if limit == 0 || len(packet) < 20 { return false }
	tcpOffset := 0
	switch packet[0] >> 4 {
	case 4:
		tcpOffset = int(packet[0]&15)*4
		if tcpOffset < 20 || len(packet) < tcpOffset+20 || packet[9] != 6 ||
			binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) { return false }
	case 6:
		if len(packet) < 60 || packet[6] != 6 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) { return false }
		tcpOffset = 40 // extension headers are deliberately left unchanged
	default: return false
	}
	tcp := packet[tcpOffset:]
	if tcp[13]&2 == 0 { return false }
	end := int(tcp[12]>>4)*4
	if end < 20 || end > len(tcp) { return false }
	mssOffset := -1
	for pos := 20; pos < end; {
		kind := tcp[pos]
		if kind == 0 { break }
		if kind == 1 { pos++; continue }
		if pos+1 >= end { return false }
		length := int(tcp[pos+1])
		if length < 2 || pos+length > end { return false }
		if kind == 2 {
			if length != 4 || mssOffset >= 0 { return false }
			mssOffset = pos+2
		}
		pos += length
	}
	if mssOffset < 0 { return false }
	old := binary.BigEndian.Uint16(tcp[mssOffset:])
	if old <= limit { return false }
	before, after := old, limit
	if mssOffset&1 != 0 { before = before<<8 | before>>8; after = after<<8 | after>>8 }
	// RFC 1624 incremental checksum, including an MSS word at odd alignment.
	sum := uint32(^binary.BigEndian.Uint16(tcp[16:18])) + uint32(^before) + uint32(after)
	for sum >> 16 != 0 { sum = (sum&0xffff) + (sum>>16) }
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))
	binary.BigEndian.PutUint16(tcp[mssOffset:], limit)
	return true
}
