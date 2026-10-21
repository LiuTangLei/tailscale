// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"tailscale.com/types/logger"
)

func TestSocketBufferRequestsRespectPlatformAndExistingSize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		minimum int
		want    []int
		fails   bool
	}{
		{"smaller-request-succeeds", 1 << 20, []int{8 << 20, 4 << 20, 2 << 20}, false},
		{"preserve-existing-buffer", 3 << 20, []int{8 << 20, 4 << 20}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests []int
			_, err := requestSocketBuffer(func(n int) error {
				requests = append(requests, n)
				if n > 2<<20 {
					return errors.New("buffer limit")
				}
				return nil
			}, 8<<20, tc.minimum)
			if !reflect.DeepEqual(requests, tc.want) || (err != nil) != tc.fails {
				t.Fatalf("requests=%v err=%v", requests, err)
			}
		})
	}
}

func TestSocketBufferDiagnosticsUseKernelValues(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	stats := configureSocketBuffers(pc, logger.Discard)
	if stats == nil {
		t.Fatal("UDP socket did not expose buffer controls")
	}
	if !stats.Measured {
		t.Skip("socket buffer measurements unavailable on this platform")
	}
	if stats.Read <= 0 || stats.Write <= 0 {
		t.Fatalf("invalid observed buffer sizes: %+v", stats)
	}
	t.Logf("kernel buffer bytes: receive=%d send=%d; last requests: receive=%d send=%d", stats.Read, stats.Write, stats.ReadRequested, stats.WriteRequested)
}
