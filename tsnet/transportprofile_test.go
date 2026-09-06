// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package tsnet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// Exercise the same LocalAPI used by `tailscale awg`, then restart real engines
// from the persisted files. No environment flags or Factory injection may hide
// a missing next-start hookup in this test.
func TestManagedTransportLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	controlURL, control := startControl(t)
	control.AllNodesSameUser = true
	control.AllOnline = true
	roots := [2]string{t.TempDir(), t.TempDir()}
	var nodes [2]*Server
	var clients [2]*local.Client
	var ips [2]netip.Addr
	start := func() {
		t.Helper()
		for i := range nodes {
			nodes[i] = &Server{Dir: roots[i], Hostname: []string{"managed-a", "managed-b"}[i], ControlURL: controlURL, Logf: t.Logf, UserLogf: t.Logf}
			st, err := nodes[i].Up(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ips[i] = st.TailscaleIPs[0]
			clients[i], err = nodes[i].LocalClient()
			if err != nil {
				t.Fatal(err)
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			ready := true
			for _, lc := range clients {
				st, err := lc.Status(ctx)
				ready = ready && err == nil && len(st.Peer) > 0
			}
			if ready {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("peers not discovered")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	stop := func() {
		for i, s := range nodes {
			if s != nil {
				s.Close()
				nodes[i] = nil
			}
		}
	}
	defer stop()
	start()
	get := func(i int) ipn.TransportControlStatus {
		t.Helper()
		s, err := clients[i].TransportStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	change := func(i int, r ipn.TransportControlRequest) ipn.TransportControlStatus {
		t.Helper()
		r.ExpectedRevision = get(i).Revision
		s, err := clients[i].ConfigureTransport(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	var cards [2]*ipn.TransportPeer
	for i := range nodes {
		st := get(i)
		if !st.Available || st.ActiveMode != "native" || st.Identity != nil || st.PendingRestart {
			t.Fatalf("initial status: %+v", st)
		}
		cards[i] = change(i, ipn.TransportControlRequest{Action: "prepare"}).Identity
		if cards[i] == nil {
			t.Fatal("missing public identity")
		}
		b, _ := json.Marshal(get(i))
		if bytes.Contains(b, []byte("PRIVATE KEY")) || bytes.Contains(b, []byte("private_key_pem")) {
			t.Fatal("secret exported")
		}
	}
	for i := range nodes {
		change(i, ipn.TransportControlRequest{Action: "add-peer", Peer: cards[i^1]})
	}
	if _, err := clients[0].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "mode", Mode: "quic-ip", ExpectedRevision: "0"}); err == nil {
		t.Fatal("stale prompt overwrote profile")
	}
	previous := "native"
	for _, mode := range []string{"quic-ip", "http3-ip", "native"} {
		for i := range nodes {
			st := change(i, ipn.TransportControlRequest{Action: "mode", Mode: mode})
			if st.ActiveMode != previous || st.DesiredMode != mode || !st.PendingRestart {
				t.Fatalf("staging changed running mode: %+v", st)
			}
		}
		stop()
		start()
		for i := range nodes {
			st := get(i)
			if st.ActiveMode != mode || st.PendingRestart || st.Identity.PublicKey != cards[i].PublicKey {
				t.Fatalf("restart did not apply: %+v", st)
			}
			if mode != "native" {
				_, err := clients[i].EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AmneziaWG: ipn.AmneziaWGPrefs{JC: 1, JMin: 50, JMax: 100}}, AmneziaWGSet: true})
				if err == nil {
					t.Fatal("legacy AWG preference update accepted by active QUIC engine")
				}
			}
			pingCtx, pingCancel := context.WithTimeout(ctx, 8*time.Second)
			pong, err := clients[i].Ping(pingCtx, ips[i^1], tailcfg.PingTSMP)
			pingCancel()
			if err != nil || pong == nil || pong.Err != "" {
				t.Fatalf("%s encrypted TSMP: %+v %v", mode, pong, err)
			}
		}
		ln, err := nodes[1].Listen("tcp", ":18088")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		want := bytes.Repeat([]byte("managed-profile-roundtrip"), 1024)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(8 * time.Second))
			b := make([]byte, len(want))
			_, err = io.ReadFull(c, b)
			if err == nil && !bytes.Equal(want, b) {
				err = io.ErrUnexpectedEOF
			}
			if err == nil {
				_, err = c.Write(b)
			}
			done <- err
		}()
		c, err := nodes[0].Dial(ctx, "tcp", net.JoinHostPort(ips[1].String(), "18088"))
		if err != nil {
			ln.Close()
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(8 * time.Second))
		_, err = c.Write(want)
		if err != nil {
			c.Close()
			ln.Close()
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		_, err = io.ReadFull(c, got)
		c.Close()
		ln.Close()
		if err != nil || !bytes.Equal(want, got) {
			t.Fatal("roundtrip failed", mode, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		for _, node := range nodes {
			stats, err := node.PacketTransportDiagnostics()
			if err != nil {
				t.Fatal(err)
			}
			if stats["mode"] != mode || stats["quic"] != (mode != "native") {
				t.Fatalf("managed runtime diagnostics reported a different carrier: %+v", stats)
			}
			if mode != "native" {
				if stats["identity_ok"] != true || stats["tls_version"] != uint16(0x0304) || stats["datagrams"] != true || stats["wireguard_encryption"] != false {
					t.Fatalf("managed carrier missing authenticated native-IP evidence: %+v", stats)
				}
				if n, ok := stats["sent_packets"].(uint64); !ok || n == 0 {
					t.Fatal("managed sender stats absent", stats)
				}
				if n, ok := stats["received_packets"].(uint64); !ok || n == 0 {
					t.Fatal("managed receiver stats absent", stats)
				}
			}
			encoded, _ := json.Marshal(stats)
			if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("private_key")) {
				t.Fatal("diagnostics exposed private identity material")
			}
		}
		previous = mode
	}
}
