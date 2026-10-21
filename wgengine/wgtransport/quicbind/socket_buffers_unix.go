// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package quicbind

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func readSocketBuffers(raw syscall.RawConn) (read, write int, ok bool) {
	err := raw.Control(func(fd uintptr) {
		var rerr, werr error
		read, rerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		write, werr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
		ok = rerr == nil && werr == nil
	})
	// Linux reports twice the configured size, including kernel bookkeeping.
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		read /= 2
		write /= 2
	}
	return read, write, ok && err == nil
}
