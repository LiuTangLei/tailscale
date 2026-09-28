// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package wgengine

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgtransport"
)

type nativeIPTestFactory struct{ transportTestFactory }

func (nativeIPTestFactory) Mode() wgtransport.Mode { return wgtransport.QUICIP }

func TestNativeIPEngineHasNoWireGuardAndRecoversRejectedProfile(t *testing.T) {
	bus := eventbustest.NewBus(t)
	backend := &transportTestBackend{keys: make(chan [32]byte, 32), removed: make(chan [32]byte, 32)}
	e, err := NewUserspaceEngine(t.Logf, Config{HealthTracker: health.NewTracker(bus), Metrics: new(usermetric.Registry), EventBus: bus,
		Transport: wgtransport.Config{Mode: wgtransport.QUICIP, Factory: nativeIPTestFactory{transportTestFactory{backend}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	u := e.(*userspaceEngine)
	if _, ok := u.packet.(*ipPacketEngine); !ok {
		t.Fatalf("native IP created %T instead of independent IP data plane", u.packet)
	}
	local := key.NewNode()
	peer := key.NewNode().Public()
	var expected atomic.Pointer[key.NodePublic]
	pub := local.Public()
	expected.Store(&pub)
	e.SetPeerPolicyFuncs(func(local, remote key.NodePublic) bool { return local == *expected.Load() && remote == peer }, func(local, remote key.NodePublic, _ netip.Addr) bool {
		return local == *expected.Load() && remote == peer
	})
	config := &wgcfg.Config{PrivateKey: local, Addresses: []netip.Prefix{netip.MustParsePrefix("100.100.99.1/32")}}
	if err := e.Reconfig(config, &router.Config{}, &dns.Config{}); err != nil {
		t.Fatal(err)
	}
	if !u.peerCurrentlyAllowed(peer) {
		t.Fatal("configured peer not admitted")
	}
	if p, ok := e.PeerByKey(peer); ok || p.IsValid() {
		t.Fatal("native IP fabricated a WireGuard device peer")
	}
	// Control-plane profile changes revoke the old LOCAL binding even when
	// the remote peer happens to retain the same key and certificate pin.
	other := key.NewNode().Public()
	expected.Store(&other)
	if u.peerCurrentlyAllowed(peer) {
		t.Fatal("old local profile remained authorized")
	}
	expected.Store(&pub)
	bad := config.Clone()
	bad.AmneziaWG = ipn.AmneziaWGPrefs{JC: 1, JMin: 64, JMax: 128}
	if err := e.Reconfig(bad, &router.Config{}, &dns.Config{}); err == nil {
		t.Fatal("native IP silently accepted AWG config")
	}
	if u.peerCurrentlyAllowed(peer) {
		t.Fatal("rejected configuration left old identity usable")
	}
	if err := e.Reconfig(config, &router.Config{}, &dns.Config{}); err != nil {
		t.Fatalf("valid config did not recover after rejection: %v", err)
	}
	if !u.peerCurrentlyAllowed(peer) {
		t.Fatal("valid config failed to restore local admission")
	}
}
