// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package transportprofile

import (
	"bytes"
	"encoding/json"
	"testing"

	"tailscale.com/ipn"
)

func TestSingleServerFlagPersistsWithoutChangingIdentity(t *testing.T) {
	p, k := newProfile(t)
	remote, _ := newProfile(t)
	var err error
	p, err = Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: remote.Identity}, k)
	if err != nil {
		t.Fatal(err)
	}
	originalCert, originalKey := p.Certificate, p.PrivateKey
	root := t.TempDir()
	revision := "0"
	for _, mode := range []string{"native", "http3-ip", "quic-ip"} {
		p.Mode = mode
		for _, enabled := range []bool{true, false} {
			before := p
			p, err = Apply(p, ipn.TransportControlRequest{Action: "server", Server: &enabled}, k)
			if err != nil {
				t.Fatal(err)
			}
			if p.Mode != mode || p.Certificate != originalCert || p.PrivateKey != originalKey || p.Identity.PublicKey != before.Identity.PublicKey || p.Peers[0] != before.Peers[0] {
				t.Fatal("server flag mutated identity, mode or peer trust")
			}
			public := p.Public("test")
			if public.Server != enabled || public.Identity.Server != enabled {
				t.Fatal("public declaration mismatch")
			}
			if before.Identity.Server {
				t.Fatal("export mutated stored identity through shared pointer")
			}
			encoded, _ := json.Marshal(public)
			if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("private_key_pem")) {
				t.Fatal("secret leaked")
			}
			revision, err = Save(root, p, revision)
			if err != nil {
				t.Fatal(err)
			}
			loaded, rev, err := Read(root)
			if err != nil || rev != revision || loaded.Server != enabled {
				t.Fatal("server flag did not survive save/read", err)
			}
			f, err := loaded.Factory()
			if err != nil {
				t.Fatal(err)
			}
			if f != nil && f.Snapshot()["server"] != (mode == "http3-ip" && enabled) {
				t.Fatal("flag leaked into non-H3 mode")
			}
		}
	}
	if _, err := Apply(p, ipn.TransportControlRequest{Action: "server"}, k); err == nil {
		t.Fatal("missing boolean accepted")
	}
}

func TestServerMetadataRefreshDoesNotRequireKeyRotation(t *testing.T) {
	p, k := newProfile(t)
	remote, _ := newProfile(t)
	var err error
	p, err = Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: remote.Identity}, k)
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{true, false} {
		updated := *remote.Identity
		updated.Server = enabled
		p, err = Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: &updated}, k)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Peers) != 1 || p.Peers[0].Server != enabled {
			t.Fatal("same-key metadata refresh failed")
		}
	}
	bad := *remote.Identity
	bad.SPKISHA256 = p.Identity.SPKISHA256
	if _, err := Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: &bad}, k); err == nil {
		t.Fatal("metadata update bypassed key pin check")
	}
}
