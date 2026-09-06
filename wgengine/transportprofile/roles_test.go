// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package transportprofile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestHTTP3RolesAreLocalAndPersistWithoutIdentityChanges(t *testing.T) {
	p, local := newProfile(t)
	remote, _ := newProfile(t)
	var err error
	p, err = Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: remote.Identity}, local)
	if err != nil {
		t.Fatal(err)
	}
	originalPrivate := p.PrivateKey
	before, _ := json.Marshal(p.Identity)
	old := p
	p, err = Apply(p, ipn.TransportControlRequest{Action: "peer-role", PublicKey: remote.LocalKey, ConnectionRole: "client"}, local)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.HTTP3PeerRoles) != 0 {
		t.Fatal("role update mutated old profile")
	}
	if p.Mode != "native" || p.PrivateKey != originalPrivate {
		t.Fatal("role change altered mode or identity")
	}
	after, _ := json.Marshal(p.Identity)
	if string(before) != string(after) || strings.Contains(string(after), "role") {
		t.Fatal("local role leaked into identity card")
	}
	root := t.TempDir()
	rev, err := Save(root, p, "0")
	if err != nil {
		t.Fatal(err)
	}
	p2, got, err := Read(root)
	if err != nil || got != rev || p2.HTTP3PeerRoles[remote.LocalKey] != "client" {
		t.Fatalf("roundtrip failed %v", err)
	}
	public := p.Public(rev)
	public.HTTP3PeerRoles[remote.LocalKey] = "server"
	if p.HTTP3PeerRoles[remote.LocalKey] != "client" {
		t.Fatal("public status aliases private profile map")
	}
	for _, mode := range []string{"http3-ip", "native", "quic-ip"} {
		p, err = Apply(p, ipn.TransportControlRequest{Action: "mode", Mode: mode}, local)
		if err != nil {
			t.Fatal(mode, err)
		}
		if p.HTTP3PeerRoles[remote.LocalKey] != "client" {
			t.Fatal("mode switch lost H3 preferences")
		}
	}
	p.Mode = "native"
	p, err = Apply(p, ipn.TransportControlRequest{Action: "peer-role", PublicKey: remote.LocalKey, ConnectionRole: "mesh"}, local)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(p)
	if strings.Contains(string(data), "http3_peer_roles") {
		t.Fatal("reset must omit new field for older release readers")
	}
	if _, err = Save(root, p, "0"); !errors.Is(err, ErrConflict) {
		t.Fatal("role staging bypassed revision check")
	}
}

func TestHTTP3RolesRejectUnknownPeersAndAreRemovedWithPeer(t *testing.T) {
	p, local := newProfile(t)
	remote, _ := newProfile(t)
	if _, err := Apply(p, ipn.TransportControlRequest{Action: "peer-role", PublicKey: remote.LocalKey, ConnectionRole: "client"}, local); err == nil {
		t.Fatal("role trusted unknown peer")
	}
	p, err := Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: remote.Identity}, local)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(p, ipn.TransportControlRequest{Action: "peer-role", PublicKey: remote.LocalKey, ConnectionRole: "browser"}, local); err == nil {
		t.Fatal("accepted fake browser role")
	}
	p, err = Apply(p, ipn.TransportControlRequest{Action: "peer-role", PublicKey: remote.LocalKey, ConnectionRole: "server"}, local)
	if err != nil {
		t.Fatal(err)
	}
	p, err = Apply(p, ipn.TransportControlRequest{Action: "remove-peer", PublicKey: remote.LocalKey}, local)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.HTTP3PeerRoles) != 0 {
		t.Fatal("removed peer retained role")
	}
}
