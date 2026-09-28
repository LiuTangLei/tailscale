// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestHTTP3StreamWaitsForTunnelInstallation(t *testing.T) {
	for _, action := range []string{"install", "request-cancel", "shutdown", "timeout", "unadmitted"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				generationCtx, shutdown := context.WithCancel(context.Background())
				defer shutdown()
				ready := make(chan struct{})
				g := &generation{ctx: generationCtx, b: &Backend{timing: defaultSessionTiming()}, h3: &http3State{tunnels: map[*quic.Conn]chan struct{}{nil: ready}}}
				if action == "unadmitted" {
					delete(g.h3.tunnels, nil)
					if g.waitHTTPTunnel(ctx, nil) {
						t.Fatal("unadmitted connection accepted")
					}
					return
				}
				result := make(chan bool, 1)
				go func() { result <- g.waitHTTPTunnel(ctx, nil) }()
				synctest.Wait()
				select {
				case <-result:
					t.Fatal("TCP request did not wait for session installation")
				default:
				}
				switch action {
				case "install":
					close(ready)
				case "request-cancel":
					cancel()
				case "shutdown":
					shutdown()
				case "timeout":
					time.Sleep(g.b.timing.authTimeout)
				}
				if got := <-result; got != (action == "install") {
					t.Fatalf("readiness=%v for %s", got, action)
				}
				if _, s := g.tcpSession(nil); s != nil {
					t.Fatal("readiness fabricated an authenticated session")
				}
			})
		})
	}
}
