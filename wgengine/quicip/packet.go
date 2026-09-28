// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package quicip implements the IP side of an authenticated datagram tunnel.
// It does not create a WireGuard Device, perform a Noise handshake, or encrypt
// packets. The carrier supplies authenticated peer identity and TLS protection;
// the host supplies live node admission, source authorization and packet policy.
package quicip

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrMalformedIP = errors.New("invalid native QUIC IP packet")

// ParseIP validates the complete packet, not merely a plausible leading nibble.
// Unlike WG, native IP frames have no trailing transport padding. IPv4 options
// and fragmented IP packets preserve their source identity. IPv6 jumbograms and
// IPv4-mapped IPv6 addresses are deliberately unsupported (no ambiguous family
// interpretation in source-policy checks).
func ParseIP(b []byte) (src, dst netip.Addr, err error) {
	if len(b) == 0 {
		return src, dst, ErrMalformedIP
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return src, dst, ErrMalformedIP
		}
		ihl := int(b[0]&15) * 4
		size := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || ihl > len(b) || size != len(b) {
			return src, dst, ErrMalformedIP
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
	case 6:
		if len(b) < 40 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
			return src, dst, ErrMalformedIP
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		if src.Is4In6() || dst.Is4In6() {
			return src, dst, ErrMalformedIP
		}
	default:
		return src, dst, ErrMalformedIP
	}
	if src.IsUnspecified() || src.IsMulticast() || dst.IsUnspecified() {
		return src, dst, ErrMalformedIP
	}
	return src, dst, nil
}
