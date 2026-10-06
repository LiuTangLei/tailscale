package netcheck

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
	"testing"
	"time"
)

// RFC8489 6.3.3 permits a supported response mapping family different from
// the request family. CanSend describes actual sending, not that mapping.
func TestSTUNSendProofUsesProbeFamily(t *testing.T) {
	for _, tc := range []struct {
		name, server, mapped string
		v4, v6               bool
	}{
		{"IPv4ProbeIPv4Mapping", "127.0.0.1:42643", "127.0.0.1:42641", true, false},
		{"IPv6ProbeIPv6Mapping", "[::1]:42643", "[::1]:42641", false, true},
		{"IPv4ProbeIPv6Mapping", "127.0.0.1:42643", "[::1]:42641", true, false},
		{"IPv6ProbeIPv4Mapping", "[::1]:42643", "127.0.0.1:42641", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t)
			c.SkipExternalNetwork = true
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			var workers sync.WaitGroup
			c.SendPacket = func(packet []byte, destination netip.AddrPort) (int, error) {
				workers.Add(1)
				defer workers.Done()
				transaction, err := stun.ParseBindingRequest(packet)
				if err != nil {
					return 0, fmt.Errorf("parse request: %w", err)
				}
				c.ReceiveSTUNPacket(stun.Response(transaction, netip.MustParseAddrPort(tc.mapped)), destination)
				<-release
				return len(packet), nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			report, err := c.GetReport(ctx, stuntest.DERPMapOf(tc.server), &GetReportOpts{OnlySTUN: true})
			unblock()
			workers.Wait()
			if err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil {
				t.Fatalf("fixture did not complete from matching reply: %v", ctx.Err())
			}
			if !report.UDP || (netip.MustParseAddrPort(tc.mapped).Addr().Is4() && !report.GlobalV4.IsValid()) || (netip.MustParseAddrPort(tc.mapped).Addr().Is6() && !report.GlobalV6.IsValid()) {
				t.Fatal("matched reply mapping not admitted")
			}
			if report.IPv4CanSend != tc.v4 || report.IPv6CanSend != tc.v6 {
				t.Fatalf("probe-family send proof=%v,%v; want=%v,%v", report.IPv4CanSend, report.IPv6CanSend, tc.v4, tc.v6)
			}
		})
	}
}
