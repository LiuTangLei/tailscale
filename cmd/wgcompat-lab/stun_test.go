// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"tailscale.com/tailcfg"
	"testing"
)

func TestPublicSTUNDoesNotChangeRelayDestination(t *testing.T) {
	relay := &tailcfg.DERPNode{Name: "private-relay", RegionID: 901, STUNPort: -1, InsecureForTests: true}
	a := &tailcfg.DERPNode{Name: "a", RegionID: 3, HostName: "a.invalid", STUNPort: 3478}
	b := &tailcfg.DERPNode{Name: "b", RegionID: 1, HostName: "b.invalid"}
	dst := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{901: {RegionID: 901, Nodes: []*tailcfg.DERPNode{relay}}}}
	public := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		3: {Nodes: []*tailcfg.DERPNode{a}},
		1: {Nodes: []*tailcfg.DERPNode{{Name: "no-stun", STUNPort: -1}, b}},
	}}
	if err := attachSTUNNodes(dst, public); err != nil {
		t.Fatal(err)
	}
	nodes := dst.Regions[901].Nodes
	if len(nodes) != 3 || nodes[2] != relay {
		t.Fatalf("lost private relay: %+v", nodes)
	}
	if nodes[0].Name != "wgcompat-stun-b" || nodes[1].Name != "wgcompat-stun-a" {
		t.Fatal("unstable probe ordering")
	}
	for _, n := range nodes[:2] {
		if !n.STUNOnly || n.InsecureForTests || n.RegionID != 901 {
			t.Fatalf("public node can become a relay: %+v", n)
		}
	}
	if a.STUNOnly || b.STUNOnly || a.RegionID != 3 || b.RegionID != 1 {
		t.Fatal("mutated public source map")
	}
	if err := attachSTUNNodes(dst, &tailcfg.DERPMap{}); err == nil {
		t.Fatal("accepted map without STUN")
	}
}
