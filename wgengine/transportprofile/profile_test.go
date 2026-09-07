// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package transportprofile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgtransport"
)

func newProfile(t *testing.T) (Profile, string) {
	t.Helper()
	k := key.NewNode().Public().String()
	p, err := NewIdentity(Profile{Version: 1, Mode: "native", Peers: []ipn.TransportPeer{}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}
func TestProfileLifecycleAndPrivateExport(t *testing.T) {
	root := t.TempDir()
	empty, rev, err := Read(root)
	if err != nil || rev != "0" || empty.Mode != "native" {
		t.Fatalf("initial: %+v %s %v", empty, rev, err)
	}
	if _, err := os.Stat(filepath.Join(root, Filename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inspection created a file")
	}
	p, k := newProfile(t)
	p2, err := NewIdentity(p, k)
	if err != nil || p2.PrivateKey != p.PrivateKey {
		t.Fatal("identity changed on repeated initialization")
	}
	rev, err = Save(root, p, "0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Save(root, p, "0"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	public, err := json.Marshal(p.Public(rev))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE KEY", "CERTIFICATE", p.PrivateKey, p.Certificate} {
		if strings.Contains(string(public), secret) {
			t.Fatal("public status contains secret material")
		}
	}
	peer, _ := newProfile(t)
	req := ipn.TransportControlRequest{Action: "add-peer", Peer: peer.Identity}
	p, err = Apply(p, req, k)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Peers) != 1 {
		t.Fatal("peer not imported")
	}
	for _, mode := range []string{"quic-ip", "http3-ip", "native"} {
		p, err = Apply(p, ipn.TransportControlRequest{Action: "mode", Mode: mode}, k)
		if err != nil {
			t.Fatal(mode, err)
		}
		rev, err = Save(root, p, rev)
		if err != nil {
			t.Fatal(err)
		}
		cfg, gotRevision, err := LoadForStart(root)
		if err != nil || gotRevision != rev || string(cfg.Mode) != mode {
			t.Fatalf("load mode=%s %+v %s %v", mode, cfg, gotRevision, err)
		}
		if mode != "native" && cfg.Factory.Mode() != wgtransport.Mode(mode) {
			t.Fatal("factory mode mismatch")
		}
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(root, Filename))
		if st.Mode().Perm() != 0600 {
			t.Fatal("profile not private")
		}
	}
}
func TestH3AutoTrustModeGeneratesIdentityWithoutPrepare(t *testing.T) {
	k := key.NewNode().Public().String()
	want, err := canonicalKey(k)
	if err != nil {
		t.Fatal(err)
	}
	p := Profile{Version: 1, Mode: "native", Peers: []ipn.TransportPeer{}}
	p, err = Apply(p, ipn.TransportControlRequest{Action: "mode", Mode: "http3-ip"}, k)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AutoTrust || p.Identity == nil || p.LocalKey != want || p.Identity.PublicKey != want {
		t.Fatalf("http3 mode did not generate auto-trust identity: %+v", p)
	}
	manual := Profile{Version: 1, Mode: "http3-ip", AutoTrust: false, Peers: []ipn.TransportPeer{}}
	manual, err = Apply(manual, ipn.TransportControlRequest{Action: "prepare"}, k)
	if err != nil {
		t.Fatal(err)
	}
	if manual.AutoTrust {
		t.Fatal("prepare auto-enabled node-key trust without an explicit request")
	}
}

func TestLoadForStartRejectsMalformedAutoTrustIdentity(t *testing.T) {
	root := t.TempDir()
	p, k := newProfile(t)
	p.Mode = "http3-ip"
	p.AutoTrust = true
	p.Certificate = "not-a-cert"
	p.PrivateKey = "not-a-key"
	p.Identity = &ipn.TransportPeer{PublicKey: k, SPKISHA256: "deadbeef"}
	if _, err := Save(root, p, "0"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadForStart(root); err == nil {
		t.Fatal("malformed auto-trust profile accepted")
	}
}

func TestInvalidImportsAndModes(t *testing.T) {
	p, k := newProfile(t)
	peer, _ := newProfile(t)
	for _, req := range []ipn.TransportControlRequest{
		{Action: "mode", Mode: "quic"}, {Action: "mode", Mode: "shell"}, {Action: "add-peer", Peer: p.Identity}, {Action: "add-peer"}, {Action: "remove-peer", PublicKey: peer.Identity.PublicKey}, {Action: "unknown"},
	} {
		if _, err := Apply(p, req, k); err == nil {
			t.Fatalf("accepted %+v", req)
		}
	}
	p, err := Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: peer.Identity}, k)
	if err != nil {
		t.Fatal(err)
	}
	p, err = Apply(p, ipn.TransportControlRequest{Action: "mode", Mode: "quic-ip"}, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(p, ipn.TransportControlRequest{Action: "validate"}, key.NewNode().Public().String()); err == nil {
		t.Fatal("accepted wrong local identity")
	}
	if _, err := Apply(p, ipn.TransportControlRequest{Action: "remove-peer", PublicKey: peer.Identity.PublicKey}, k); err == nil {
		t.Fatal("removed last enabled peer")
	}
	changed := *peer.Identity
	changed.SPKISHA256 = strings.Repeat("ab", 32)
	if _, err := Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: &changed}, k); err == nil {
		t.Fatal("silently replaced trusted key")
	}
	duplicate := *peer.Identity
	duplicate.PublicKey = strings.Repeat("cd", 32)
	if _, err := Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: &duplicate}, k); err == nil {
		t.Fatal("duplicate TLS pin accepted")
	}
}
func TestBadProfileFailsClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, Filename)
	if err := os.WriteFile(path, []byte(`{"version":1,"mode":"quic"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadForStart(root); err == nil {
		t.Fatal("legacy profile accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"mode":"native","unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(root); err == nil {
		t.Fatal("unknown field accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Read(root); err == nil {
			t.Fatal("publicly readable private file accepted")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "other")
		os.WriteFile(target, []byte(`{}`), 0600)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Read(root); err == nil {
			t.Fatal("symlink profile accepted")
		}
	}
}
