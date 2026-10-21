// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"encoding/binary"
	"errors"

	"github.com/quic-go/quic-go/quicvarint"
)

var errInvalidRepairACK = errors.New("invalid TCP repair ACK")

// v2 compresses each 64-bit bitmap word as zero, all ones, or eight literal
// bytes. Normal in-order traffic needs only a few bytes instead of a fixed 49.
// Duplicate feedback lets the sender tolerate observed reordering on this path.
type repairAcknowledgment struct {
	id, largest, duplicates uint64
	bits                    [4]uint64
}

func appendRepairACK(b []byte, a repairAcknowledgment) []byte {
	b = append(b, frameTCPAck)
	b = quicvarint.Append(b, a.id)
	b = quicvarint.Append(b, a.largest)
	b = quicvarint.Append(b, a.duplicates)
	flags := len(b)
	b = append(b, 0)
	for i, v := range a.bits {
		switch v {
		case 0:
		case ^uint64(0):
			b[flags] |= 1 << (2 * i)
		default:
			b[flags] |= 2 << (2 * i)
			b = binary.BigEndian.AppendUint64(b, v)
		}
	}
	return b
}

func parseRepairACK(b []byte) (a repairAcknowledgment, err error) {
	if len(b) < 5 || len(b) > 58 || b[0] != frameTCPAck {
		return a, errInvalidRepairACK
	}
	b = b[1:]
	for _, v := range []*uint64{&a.id, &a.largest, &a.duplicates} {
		value, n, e := quicvarint.Parse(b)
		if e != nil {
			return a, errInvalidRepairACK
		}
		*v = value
		b = b[n:]
	}
	if len(b) == 0 || a.id == 0 || a.largest == 0 {
		return a, errInvalidRepairACK
	}
	flags := b[0]
	b = b[1:]
	for i := range a.bits {
		switch flags >> (2 * i) & 3 {
		case 0:
		case 1:
			a.bits[i] = ^uint64(0)
		case 2:
			if len(b) < 8 {
				return a, errInvalidRepairACK
			}
			a.bits[i] = binary.BigEndian.Uint64(b)
			b = b[8:]
		default:
			return a, errInvalidRepairACK
		}
	}
	if len(b) != 0 || a.bits[0]&1 == 0 {
		return a, errInvalidRepairACK
	}
	return a, nil
}
