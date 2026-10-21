// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package quicbind

import "syscall"

func readSocketBuffers(syscall.RawConn) (int, int, bool) { return 0, 0, false }
