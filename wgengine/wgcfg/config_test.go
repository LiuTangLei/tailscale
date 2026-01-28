// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"reflect"
	"testing"
)

// Tests that [Config.Equal] tests all fields of [Config], even ones
// that might get added in the future.
func TestConfigEqual(t *testing.T) {
	rt := reflect.TypeFor[Config]()
	for i := range rt.NumField() {
		sf := rt.Field(i)
		switch sf.Name {
		case "Name", "NodeID", "PrivateKey", "MTU", "Addresses", "DNS", "Peers",
			"NetworkLogging",
			"AmneziaJC", "AmneziaJMin", "AmneziaJMax", "AmneziaS1", "AmneziaS2",
			"AmneziaS3", "AmneziaS4", "AmneziaI1", "AmneziaI2", "AmneziaI3",
			"AmneziaI4", "AmneziaI5", "AmneziaH1", "AmneziaH2", "AmneziaH3", "AmneziaH4":
			// These are compared in [Config.Equal].
		default:
			t.Errorf("Have you added field %q to Config.Equal? Do so if not, and then update TestConfigEqual", sf.Name)
		}
	}
}

// Tests that [Peer.Equal] tests all fields of [Peer], even ones
// that might get added in the future.
func TestPeerEqual(t *testing.T) {
	rt := reflect.TypeFor[Peer]()
	for i := range rt.NumField() {
		sf := rt.Field(i)
		switch sf.Name {
		case "PublicKey", "DiscoKey", "AllowedIPs", "IsJailed",
			"PersistentKeepalive", "V4MasqAddr", "V6MasqAddr", "WGEndpoint":
			// These are compared in [Peer.Equal].
		default:
			t.Errorf("Have you added field %q to Peer.Equal? Do so if not, and then update TestPeerEqual", sf.Name)
		}
	}
}
