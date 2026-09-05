// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgtransport"
)

func TestTransportRejectedBeforeEngineResources(t *testing.T) {
	for _, mode := range []wgtransport.Mode{wgtransport.QUIC, "misspelled"} {
		// Missing mandatory health/metrics would panic/fail later. Transport
		// validation must happen first, before sockets or TUNs are allocated.
		e, err := NewUserspaceEngine(t.Logf, Config{Transport: wgtransport.Config{Mode: mode}})
		if e != nil || err == nil {
			t.Fatalf("mode %q: engine=%v err=%v", mode, e, err)
		}
		if mode == wgtransport.QUIC && !errors.Is(err, wgtransport.ErrUnsupported) {
			t.Fatal(err)
		}
	}
}

type transportTestFactory struct{ b *transportTestBackend }

func (f transportTestFactory) Mode() wgtransport.Mode { return wgtransport.QUIC }
func (f transportTestFactory) New(h wgtransport.Host) (wgtransport.Backend, error) {
	f.b.bind = h.Bind
	return f.b, nil
}

type transportTestBackend struct {
	bind    conn.Bind
	keys    chan [32]byte
	removed chan [32]byte
	closed  atomic.Int32
}

func (b *transportTestBackend) Bind() conn.Bind                 { return b.bind }
func (b *transportTestBackend) Close() error                    { b.closed.Add(1); return nil }
func (b *transportTestBackend) LocalIdentityChanged(k [32]byte) { b.keys <- k }
func (b *transportTestBackend) PeerRemoved(k [32]byte)          { b.removed <- k }

func TestTransportEngineLifecycle(t *testing.T) {
	if !wgtransport.LegacyWGOverQUIC {
		t.Skip("legacy WG-over-QUIC lifecycle requires development tag; native IP has separate tests")
	}
	bus := eventbustest.NewBus(t)
	b := &transportTestBackend{keys: make(chan [32]byte, 8), removed: make(chan [32]byte, 8)}
	// This is a test double for the future extension point, NOT a QUIC implementation.
	e, err := NewUserspaceEngine(t.Logf, Config{
		HealthTracker: health.NewTracker(bus), Metrics: new(usermetric.Registry), EventBus: bus,
		Transport: wgtransport.Config{Mode: wgtransport.QUIC, Factory: transportTestFactory{b}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	k := key.NewNode()
	if err := e.Reconfig(&wgcfg.Config{PrivateKey: k, Addresses: []netip.Prefix{netip.MustParsePrefix("100.100.99.1/32")}}, &router.Config{}, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-b.keys:
		if got != k.Public().Raw32() {
			t.Fatal("wrong public identity")
		}
	default:
		t.Fatal("identity change not delivered")
	}
	peer := key.NewNode().Public()
	e.ResetDevicePeer(peer)
	e.SetPeerConfigFunc(func(key.NodePublic) ([]netip.Prefix, bool) { return nil, false })
	e.SyncDevicePeer(peer)
	for range 2 {
		select {
		case got := <-b.removed:
			if got != peer.Raw32() {
				t.Fatal("wrong removed identity")
			}
		default:
			t.Fatal("missing removal callback")
		}
	}
	if _, err := e.(*userspaceEngine).getStatus(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.removed:
		t.Fatal("status iteration unexpectedly removed a peer")
	default:
	}
	e.Close()
	e.Close()
	if b.closed.Load() != 1 {
		t.Fatalf("backend final closes=%d", b.closed.Load())
	}
}
