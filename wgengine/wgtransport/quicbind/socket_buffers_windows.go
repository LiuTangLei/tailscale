// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func readSocketBuffers(raw syscall.RawConn) (read, write int, ok bool) {
	err := raw.Control(func(fd uintptr) {
		var rerr, werr error
		read, rerr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF)
		write, werr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF)
		ok = rerr == nil && werr == nil
	})
	return read, write, ok && err == nil
}
