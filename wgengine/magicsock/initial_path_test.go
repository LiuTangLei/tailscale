package magicsock

import (
	"net/netip"
	"tailscale.com/disco"
	"tailscale.com/envknob"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/ringlog"
	"testing"
	"testing/synctest"
	"time"
)

func TestInitialPathSignalRequiresVerifiedDirectPong(t *testing.T) {
	for _, name := range []string{"direct", "unknown-tx", "relay", "stale-candidate"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "")
				now := mono.Now()
				src := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:12345")}
				if name == "relay" {
					src.ap = netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 901)
				}
				c := &Conn{logf: logger.Discard, peerMap: newPeerMap()}
				c.discoAtomic.Set(key.NewDisco())
				de := &endpoint{c: c, sentPing: make(map[stun.TxID]sentPing), endpointState: map[netip.AddrPort]*endpointState{src.ap: {}}, debugUpdates: ringlog.New[EndpointChange](10)}
				signal := de.InitialPathReady()
				if signal == nil {
					t.Fatal("cold path has no signal")
				}
				if de.InitialPathReady() != signal {
					t.Fatal("cold waiters did not share one signal")
				}
				select {
				case <-signal:
					t.Fatal("path ready before Pong")
				default:
				}
				tx := stun.NewTxID()
				timer := time.NewTimer(time.Hour)
				timer.Stop()
				de.sentPing[tx] = sentPing{to: src, at: now.Add(-10 * time.Millisecond), timer: timer, purpose: pingDiscovery}
				if name == "unknown-tx" {
					tx = stun.NewTxID()
				}
				if name == "stale-candidate" {
					delete(de.endpointState, src.ap)
				}
				c.mu.Lock()
				de.handlePongConnLocked(&disco.Pong{TxID: tx, Src: src.ap}, &discoInfo{discoKey: key.NewDisco().Public()}, src)
				c.mu.Unlock()
				ready := false
				select {
				case <-signal:
					ready = true
				default:
				}
				if ready != (name == "direct") {
					t.Fatalf("ready=%v", ready)
				}
				if ready && de.InitialPathReady() != nil {
					t.Fatal("trusted path should not install a new waiter")
				}
				de.mu.Lock()
				de.invalidateDiscoPathLocked()
				de.mu.Unlock()
			})
		})
	}
}

func TestInitialPathSignalSkippedForIneligibleEndpoint(t *testing.T) {
	for _, name := range []string{"expired", "wireguard", "disabled", "trusted"} {
		t.Run(name, func(t *testing.T) {
			envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", map[bool]string{true: "true", false: ""}[name == "disabled"])
			de := &endpoint{expired: name == "expired", isWireguardOnly: name == "wireguard"}
			if name == "trusted" {
				de.bestAddr.epAddr.ap = netip.MustParseAddrPort("192.0.2.1:1")
				de.trustBestAddrUntil = mono.Now().Add(time.Hour)
			}
			if de.InitialPathReady() != nil {
				t.Fatal("ineligible path installed a signal")
			}
		})
	}
}
