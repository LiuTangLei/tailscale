// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// Exercise login -> one atomic mode change -> restart -> authenticated IP
// without preparing identities, importing cards or injecting a test Factory.
// A third peer is added after the two H3 engines are already running.
func TestManagedH3AutomaticTrustAndLatePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	url, control := startControl(t)
	control.AllNodesSameUser = true
	control.AllOnline = true
	var nodes [3]*Server
	var clients [3]*local.Client
	var addresses [3]netip.Addr
	var originalKeys [3]string
	var roots [3]string
	for i := range roots {
		roots[i] = t.TempDir()
	}
	defer func() {
		for _, s := range nodes {
			if s != nil {
				s.Close()
			}
		}
	}()
	start := func(i int) {
		t.Helper()
		nodes[i] = &Server{Dir: roots[i], Hostname: fmt.Sprintf("automatic-%d", i), ControlURL: url, Logf: t.Logf, UserLogf: t.Logf}
		status, err := nodes[i].Up(ctx)
		if err != nil {
			t.Fatal(err)
		}
		addresses[i] = status.TailscaleIPs[0]
		clients[i], err = nodes[i].LocalClient()
		if err != nil {
			t.Fatal(err)
		}
		if originalKeys[i] == "" {
			originalKeys[i] = status.Self.PublicKey.String()
		} else if originalKeys[i] != status.Self.PublicKey.String() {
			t.Fatal("mode restart changed node key")
		}
	}
	stage := func(i int, mode string) {
		t.Helper()
		before, err := clients[i].TransportStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		after, err := clients[i].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "mode", Mode: mode, ExpectedRevision: before.Revision})
		if err != nil {
			t.Fatal(err)
		}
		if after.ActiveMode != before.ActiveMode || after.DesiredMode != mode {
			t.Fatal("mode staging misreported active state")
		}
		if mode == "http3-ip" && (after.Identity == nil || len(after.Peers) != 0 || !after.AutoTrust || after.Authentication != "node-key") {
			t.Fatalf("not automatic zero-card configuration: %+v", after)
		}
	}
	restart := func(i int) { t.Helper(); nodes[i].Close(); nodes[i] = nil; start(i) }
	for i := range 2 {
		start(i)
		stage(i, "http3-ip")
	}
	st, err := clients[1].TransportStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	if _, err := clients[1].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "server", Server: &yes, ExpectedRevision: st.Revision}); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		restart(i)
	}
	// Joining a third node requires no edits or restart on the first two.
	start(2)
	stage(2, "http3-ip")
	restart(2)
	for i := range 3 {
		deadline := time.Now().Add(8 * time.Second)
		for {
			st, err := clients[i].Status(ctx)
			if err == nil && len(st.Peer) == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("late peer was not distributed")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for round := range 3 {
		for i := range 3 {
			for j := range 3 {
				if i == j {
					continue
				}
				probeCtx, done := context.WithTimeout(ctx, 8*time.Second)
				pong, err := clients[i].Ping(probeCtx, addresses[j], tailcfg.PingTSMP)
				done()
				if err != nil || pong == nil || pong.Err != "" {
					t.Fatalf("round%d %d->%d no-card encrypted TSMP: %+v %v", round, i, j, pong, err)
				}
			}
		}
	}
	var senders, receivers, handlers sync.WaitGroup
	failures := make(chan error, 16)
	var listeners []net.Listener
	for to := range 3 {
		ln, err := nodes[to].Listen("tcp", ":18086")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		listeners = append(listeners, ln)
		receivers.Add(1)
		go func() {
			defer receivers.Done()
			for range 2 {
				c, err := ln.Accept()
				if err != nil {
					failures <- fmt.Errorf("node %d accept: %w", to, err)
					return
				}
				// Keep accepting while each echo runs. tsnet intentionally has an
				// unbuffered accept queue with a one-second handoff timeout.
				handlers.Add(1)
				go func(c net.Conn) {
					defer handlers.Done()
					defer c.Close()
					c.SetDeadline(time.Now().Add(15 * time.Second))
					b := make([]byte, 64<<10)
					_, err := io.ReadFull(c, b)
					if err == nil {
						_, err = c.Write(b)
					}
					if err != nil {
						failures <- fmt.Errorf("node %d echo: %w", to, err)
					}
				}(c)
			}
		}()
	}
	for from := range 3 {
		for to := range 3 {
			if from == to {
				continue
			}
			senders.Add(1)
			go func() {
				defer senders.Done()
				dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				c, err := nodes[from].Dial(dialCtx, "tcp", net.JoinHostPort(addresses[to].String(), "18086"))
				if err != nil {
					failures <- fmt.Errorf("%d->%d dial: %w", from, to, err)
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				want := bytes.Repeat([]byte{byte(from), byte(to)}, 32<<10)
				if _, err = c.Write(want); err != nil {
					failures <- fmt.Errorf("%d->%d write: %w", from, to, err)
					return
				}
				got := make([]byte, len(want))
				_, err = io.ReadFull(c, got)
				if err != nil {
					failures <- fmt.Errorf("%d->%d read: %w", from, to, err)
					return
				}
				if !bytes.Equal(got, want) {
					failures <- fmt.Errorf("corrupt %d->%d", from, to)
				}
			}()
		}
	}
	senders.Wait()
	// Failed clients must not leave listeners blocked forever waiting for a
	// connection that will never arrive. Preserve their original errors.
	for _, ln := range listeners {
		ln.Close()
	}
	receivers.Wait()
	handlers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		for i, s := range nodes {
			stats, err := s.PacketTransportDiagnostics()
			t.Logf("node %d diagnostics: %+v (%v)", i, stats, err)
		}
		t.FailNow()
	}
	// Explicitly returning the whole node to native retains its node identity.
	for i := range 3 {
		stage(i, "native")
		restart(i)
	}
	for i := range 3 {
		st, err := clients[i].TransportStatus(ctx)
		if err != nil || st.ActiveMode != "native" || st.PendingRestart {
			t.Fatalf("native recovery: %+v %v", st, err)
		}
	}
}
