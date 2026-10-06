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

// A matched reply can complete/cancel the probe set while SendPacket is
// still returning. The returned snapshot must include proof of that send.
func TestMatchedSTUNReplyBeforeSendReturn(t *testing.T) {
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
			return 0, fmt.Errorf("parse fixture request: %w", err)
		}
		c.ReceiveSTUNPacket(stun.Response(transaction, netip.MustParseAddrPort("127.0.0.1:42641")), destination)
		<-release
		return len(packet), nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	report, err := c.GetReport(ctx, stuntest.DERPMapOf("127.0.0.1:42643"), &GetReportOpts{OnlySTUN: true})
	unblock()
	workers.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatalf("fixture probe did not complete from matched reply: %v", ctx.Err())
	}
	if !report.UDP || !report.IPv4 || !report.GlobalV4.IsValid() {
		t.Fatalf("matched reply not admitted: %+v", report)
	}
	if !report.IPv4CanSend {
		t.Fatal("matched IPv4 STUN response admitted, but returned report incorrectly says IPv4 cannot send")
	}
}
