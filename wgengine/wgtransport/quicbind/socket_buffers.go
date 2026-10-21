// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"net"
	"syscall"

	"tailscale.com/types/logger"
)

type socketBufferStats struct {
	ReadRequested  int    `json:"read_requested_bytes"`
	WriteRequested int    `json:"write_requested_bytes"`
	Read           int    `json:"read_bytes"`
	Write          int    `json:"write_bytes"`
	Measured       bool   `json:"measured"`
	ReadError      string `json:"read_error,omitempty"`
	WriteError     string `json:"write_error,omitempty"`
}

// Some systems reject an oversized request instead of capping it. A smaller
// successful request is preferable to silently keeping the system default.
func requestSocketBuffer(set func(int) error, target, minimum int) (int, error) {
	for {
		err := set(target)
		if err == nil || target/2 < minimum {
			return target, err
		}
		target /= 2
	}
}

func configureSocketBuffers(pc net.PacketConn, logf logger.Logf) *socketBufferStats {
	buffered, ok := pc.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	})
	if !ok {
		return nil
	}
	stats := new(socketBufferStats)
	measure := func() {
		if c, ok := pc.(interface {
			SyscallConn() (syscall.RawConn, error)
		}); ok {
			if raw, err := c.SyscallConn(); err == nil {
				stats.Read, stats.Write, stats.Measured = readSocketBuffers(raw)
			}
		}
	}
	measure()
	// Never shrink a larger host-provided buffer.
	if stats.Read < 8<<20 {
		requested, err := requestSocketBuffer(buffered.SetReadBuffer, 8<<20, max(1<<20, stats.Read))
		stats.ReadRequested = requested
		if err != nil {
			stats.ReadError = err.Error()
		}
	}
	if stats.Write < 4<<20 {
		requested, err := requestSocketBuffer(buffered.SetWriteBuffer, 4<<20, max(1<<20, stats.Write))
		stats.WriteRequested = requested
		if err != nil {
			stats.WriteError = err.Error()
		}
	}
	measure()
	if stats.ReadError != "" || stats.WriteError != "" || (stats.Measured && stats.Read < 1<<20) {
		logf("http3-ip: UDP socket buffers: receive=%d send=%d measured=%v receive_error=%q send_error=%q", stats.Read, stats.Write, stats.Measured, stats.ReadError, stats.WriteError)
	}
	return stats
}
