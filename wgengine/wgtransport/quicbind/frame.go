// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"encoding/binary"
	"errors"
	"time"
)

const (
	frameRaw         byte = 0
	frameFragment    byte = 1
	fragmentHeader        = 9
	maxPacket             = 65535
	maxAssemblies         = 8
	assemblyLifetime      = 2 * time.Second
)

type byteRange struct{ start, end int }
type assembly struct {
	data            []byte
	spans           [64]byteRange
	count, received int
	expires         time.Time
}

// reassembler is owned by ONE QUIC receive goroutine. Allocation and lifetime
// are bounded, overlapping fragments fail closed, and partial packets are never
// delivered to WireGuard. Complete single-frame packets have no reassembly copy.
type reassembler struct{ messages map[uint32]*assembly }

func (r *reassembler) consume(frame []byte, now time.Time) ([]byte, error) {
	if len(frame) < 2 {
		return nil, errors.New("short QUIC-WG frame")
	}
	if frame[0] == frameRaw {
		if len(frame)-1 > maxPacket {
			return nil, errors.New("oversized WG packet")
		}
		return frame[1:], nil
	}
	if frame[0] != frameFragment || len(frame) <= fragmentHeader {
		return nil, errors.New("invalid QUIC-WG frame type/length")
	}
	id := binary.BigEndian.Uint32(frame[1:5])
	total := int(binary.BigEndian.Uint16(frame[5:7]))
	start := int(binary.BigEndian.Uint16(frame[7:9]))
	end := start + len(frame) - fragmentHeader
	if total < 1 || end > total || end <= start {
		return nil, errors.New("fragment bounds")
	}
	if r.messages == nil {
		r.messages = make(map[uint32]*assembly)
	}
	for id, a := range r.messages {
		if !now.Before(a.expires) {
			delete(r.messages, id)
		}
	}
	a := r.messages[id]
	if a == nil {
		if len(r.messages) >= maxAssemblies {
			return nil, errors.New("fragment assembly limit")
		}
		a = &assembly{data: make([]byte, total), expires: now.Add(assemblyLifetime)}
		r.messages[id] = a
	}
	if len(a.data) != total {
		delete(r.messages, id)
		return nil, errors.New("fragment total changed")
	}
	for _, span := range a.spans[:a.count] {
		if start < span.end && end > span.start {
			if start == span.start && end == span.end {
				return nil, nil
			} // QUIC-level/application duplicate
			delete(r.messages, id)
			return nil, errors.New("overlapping fragment")
		}
	}
	if a.count == len(a.spans) {
		delete(r.messages, id)
		return nil, errors.New("too many fragments")
	}
	copy(a.data[start:end], frame[fragmentHeader:])
	a.spans[a.count] = byteRange{start, end}
	a.count++
	a.received += end - start
	if a.received != total {
		return nil, nil
	}
	delete(r.messages, id)
	return a.data, nil
}
