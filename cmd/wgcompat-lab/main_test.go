// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"context"
	"net/http/httptest"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"testing"
	"time"
)

func TestLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		if err := requireLoopback(addr); err != nil {
			t.Fatal(err)
		}
	}
	for _, addr := range []string{"0.0.0.0:1234", ":1234", "example.com:1234"} {
		if err := requireLoopback(addr); err == nil {
			t.Fatalf("accepted %s", addr)
		}
	}
}
func TestProfiles(t *testing.T) {
	for _, name := range []string{"standard", "awg2", "awg3", "awg31"} {
		p, err := profile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := ipn.ValidateAmneziaWGConfig(p); err != nil {
			t.Fatal(err)
		}
		if p.IsV31() != (name == "awg31") {
			t.Fatalf("3.1 flag leak in %s", name)
		}
		if p.IsZero() != (name == "standard") {
			t.Fatalf("standard mismatch in %s", name)
		}
	}
}
func TestLocalControlStartup(t *testing.T) {
	derpMap, closeDERP, err := startLabDERP("127.0.0.1:0", t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer closeDERP()
	c := &testcontrol.Server{AllNodesSameUser: true, AllOnline: true, DERPMap: derpMap, Logf: t.Logf}
	hs := httptest.NewServer(c)
	defer hs.Close()
	c.ExplicitBaseURL = hs.URL
	s := &tsnet.Server{Dir: t.TempDir(), Hostname: "wgcompat-unit", ControlURL: hs.URL, Logf: t.Logf, UserLogf: t.Logf}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	lc, err := s.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AmneziaWG: ipn.AmneziaWGPrefs{}}, AmneziaWGSet: true}); err != nil {
		t.Fatal(err)
	}
	st, err := s.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.BackendState != "Running" || len(st.TailscaleIPs) == 0 {
		t.Fatalf("not up: %+v", st)
	}
}
