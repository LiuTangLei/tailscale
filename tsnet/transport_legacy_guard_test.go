// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// This uses real engines and LocalAPI. The third peer intentionally remains
// native-only. It is a wire-mode fixture, not a test of an older release binary.
func TestManagedTransportDoesNotSilentlyDisconnectNativePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	url, control := startControl(t)
	control.AllNodesSameUser, control.AllOnline = true, true
	var nodes [3]*Server
	var clients [3]*local.Client
	for i := range nodes {
		s := &Server{Dir: t.TempDir(), Hostname: []string{"upgrade-a", "upgrade-b", "native-peer"}[i], ControlURL: url, Logf: t.Logf, UserLogf: t.Logf}
		nodes[i] = s
		t.Cleanup(func() { s.Close() })
		if _, err := s.Up(ctx); err != nil {
			t.Fatal(err)
		}
		var err error
		clients[i], err = s.LocalClient()
		if err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ready := true
		for _, lc := range clients {
			st, err := lc.Status(ctx)
			ready = ready && err == nil && len(st.Peer) == 2
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("three-node control map not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var cards [2]*ipn.TransportPeer
	for i := range cards {
		st, err := clients[i].TransportStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		st, err = clients[i].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "prepare", ExpectedRevision: st.Revision})
		if err != nil {
			t.Fatal(err)
		}
		cards[i] = st.Identity
	}
	st, err := clients[0].TransportStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st, err = clients[0].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "add-peer", ExpectedRevision: st.Revision, Peer: cards[1]})
	if err != nil {
		t.Fatal(err)
	}
	before := st.Revision
	if st.MixedPeerSupport || len(st.UnconfiguredPeers) != 1 {
		t.Fatalf("misleading compatibility status: %+v", st)
	}
	for _, mode := range []string{"quic-ip", "http3-ip"} {
		_, err = clients[0].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "mode", Mode: mode, ExpectedRevision: before})
		if err == nil || !strings.Contains(err.Error(), "routable peers") {
			t.Fatalf("%s must refuse known isolation: %v", mode, err)
		}
		st, err = clients[0].TransportStatus(ctx)
		if err != nil || st.Revision != before || st.ActiveMode != "native" || st.DesiredMode != "native" || st.PendingRestart {
			t.Fatalf("rejected change mutated config: %+v %v", st, err)
		}
	}
	for _, pair := range [][2]int{{0, 2}, {2, 0}} {
		remote, err := clients[pair[1]].Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pingCtx, done := context.WithTimeout(ctx, 8*time.Second)
		pong, err := clients[pair[0]].Ping(pingCtx, remote.TailscaleIPs[0], tailcfg.PingTSMP)
		done()
		if err != nil || pong == nil || pong.Err != "" {
			t.Fatalf("native peer lost encrypted reachability: %+v %v", pong, err)
		}
	}
}
