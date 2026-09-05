// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build cgo && (ios || android)

// quic-mobilecheck is an ABI/link fixture, not a mobile application or daemon.
// It avoids importing the laboratory control server, which is intentionally
// excluded from iOS builds. No service is started by the exported validation.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"encoding/json"
	"net"
	"unsafe"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/wgengine/wgtransport"
	"tailscale.com/wgengine/wgtransport/quicbind"
)

//export HTTP3IPValidateConfiguration
func HTTP3IPValidateConfiguration(data *C.char, size C.int) C.int {
	if data == nil || size < 1 || size > 1<<20 {
		return -1
	}
	var cfg quicbind.Config
	if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(data), size), &cfg); err != nil {
		return -1
	}
	f, err := quicbind.NewFactory(cfg)
	if err != nil {
		return -2
	}
	listener := new(net.ListenConfig)
	b, err := f.New(wgtransport.Host{Bind: conn.NewDefaultBind(), ListenPacket: listener.ListenPacket, PeerAllowed: func([32]byte) bool { return false }})
	if err != nil {
		return -3
	}
	// Retain and link the real carrier interface without opening any socket.
	if b.Bind().BatchSize() < 1 {
		_ = b.Close()
		return -4
	}
	_ = b.Close()
	return 0
}

func main() {}
