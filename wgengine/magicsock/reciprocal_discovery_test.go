// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/net/stun"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestReciprocalDiscoveryKeepsTrustAndBoundsChallenges(t *testing.T) {
	for _, name := range []string{"cold", "expired-trust", "relay", "trusted", "recent", "expired-peer", "wireguard-only", "unknown-source", "disabled"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", map[bool]string{true: "true", false: ""}[name == "disabled"])
				src := netip.MustParseAddrPort("192.0.2.1:12345")
				now := mono.Now()
				c := &Conn{closed: true, logf: logger.Discard}
				c.discoAtomic.Set(key.NewDisco())
				c.peerMTUEnabled.Store(true)
				de := &endpoint{c: c, publicKey: key.NewNode().Public(), sentPing: make(map[stun.TxID]sentPing), endpointState: map[netip.AddrPort]*endpointState{src: {}}}
				de.disco.Store(&endpointDisco{controlKey: key.NewDisco().Public()})
				want := false
				switch name {
				case "cold":
					want = true
				case "expired-trust":
					de.bestAddr.epAddr.ap = src
					de.trustBestAddrUntil = now.Add(-time.Second)
					want = true
				case "relay":
					de.bestAddr.epAddr.ap = netip.MustParseAddrPort("127.3.3.40:901")
					de.trustBestAddrUntil = now.Add(time.Hour)
					want = true
				case "trusted":
					de.bestAddr.epAddr.ap = src
					de.trustBestAddrUntil = now.Add(time.Hour)
				case "recent":
					de.endpointState[src].lastPing = now
				case "expired-peer":
					de.expired = true
				case "wireguard-only":
					de.isWireguardOnly = true
				case "unknown-source":
					delete(de.endpointState, src)
				}
				beforeAddr, beforeTrust := de.bestAddr, de.trustBestAddrUntil
				// Hold Conn.mu so the asynchronous send cannot retire the
				// scheduled challenge until its ownership is inspected.
				c.mu.Lock()
				de.maybeProbeDiscoveredEndpoint(src)
				de.maybeProbeDiscoveredEndpoint(src)
				de.mu.Lock()
				count := 0
				if want {
					count = 1
				}
				if len(de.sentPing) != count {
					t.Errorf("challenges=%d want=%d", len(de.sentPing), count)
				}
				if de.bestAddr != beforeAddr || de.trustBestAddrUntil != beforeTrust {
					t.Error("Ping changed trusted route without Pong verification")
				}
				for _, p := range de.sentPing {
					if p.purpose != pingHeartbeat || p.size != 0 {
						t.Error("reciprocal discovery scheduled an MTU probe burst")
					}
				}
				de.mu.Unlock()
				c.mu.Unlock()
				synctest.Wait()
			})
		})
	}
}

func TestReciprocalDiscoveryDoesNotSpendSendDiscoveryBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "")
		src := netip.MustParseAddrPort("192.0.2.1:12345")
		c := &Conn{closed: true, logf: logger.Discard}
		c.discoAtomic.Set(key.NewDisco())
		de := &endpoint{c: c, publicKey: key.NewNode().Public(), sentPing: make(map[stun.TxID]sentPing), endpointState: map[netip.AddrPort]*endpointState{src: {}}}
		de.disco.Store(&endpointDisco{controlKey: key.NewDisco().Public()})
		c.mu.Lock()
		de.maybeProbeDiscoveredEndpoint(src)
		de.mu.Lock()
		if !de.endpointState[src].lastPing.IsZero() {
			t.Error("reverse challenge consumed normal discovery budget")
		}
		before := len(de.sentPing)
		de.sendDiscoPingsLocked(mono.Now(), false)
		if len(de.sentPing) <= before {
			t.Error("normal send could not retry an unanswered reverse challenge")
		}
		de.mu.Unlock()
		c.mu.Unlock()
		synctest.Wait()
	})
}

func TestReciprocalDiscoveryBudgetResetWithDiscoIdentity(t *testing.T) {
	now := mono.Now()
	src := netip.MustParseAddrPort("192.0.2.1:12345")
	de := &endpoint{endpointState: map[netip.AddrPort]*endpointState{src: {lastPing: now, lastReversePing: now}}, sentPing: make(map[stun.TxID]sentPing)}
	de.mu.Lock()
	de.invalidateDiscoPathLocked()
	de.mu.Unlock()
	if !de.endpointState[src].lastPing.IsZero() || !de.endpointState[src].lastReversePing.IsZero() {
		t.Error("identity reset retained discovery budgets")
	}
}
