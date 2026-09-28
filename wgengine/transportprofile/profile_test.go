// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package transportprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/ipn"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgtransport"
	"tailscale.com/wgengine/wgtransport/nodeauth"
	"tailscale.com/wgengine/wgtransport/quicbind"
)

func TestLegacyRawProfileMigratesToH3WithoutChangingTrust(t *testing.T) {
	p, k := newProfile(t)
	remote, _ := newProfile(t)
	p.Mode, p.Server = "quic-ip", true
	p.Identity.HTTP3URL = ""
	remote.Identity.HTTP3URL = ""
	p.Peers = []ipn.TransportPeer{*remote.Identity}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, Filename)
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, rev, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Mode != "http3-ip" || loaded.AutoTrust || !loaded.Server || loaded.Certificate != p.Certificate || loaded.PrivateKey != p.PrivateKey || loaded.Peers[0].SPKISHA256 != remote.Identity.SPKISHA256 || loaded.Peers[0].PublicKey != remote.Identity.PublicKey {
		t.Fatal("migration changed identity, server declaration or pinned trust")
	}
	if loaded.Identity.HTTP3URL == "" || loaded.Peers[0].HTTP3URL == "" || p.Identity.HTTP3URL != "" || p.Peers[0].HTTP3URL != "" {
		t.Fatal("H3 authority missing or original profile mutated")
	}
	cfg, startRev, err := LoadForStart(root)
	if err != nil || cfg.Mode != wgtransport.HTTP3IP || startRev != rev {
		t.Fatalf("legacy startup: mode=%s err=%v", cfg.Mode, err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, encoded) {
		t.Fatal("loading rewrote the stored legacy profile")
	}
	changed := loaded.Peers[0]
	changed.SPKISHA256 = strings.Repeat("ab", 32)
	if _, err := Apply(loaded, ipn.TransportControlRequest{Action: "add-peer", Peer: &changed}, k); err == nil {
		t.Fatal("migration allowed replacement of an existing peer pin")
	}
	if err := loaded.Validate(key.NewNode().Public().String()); err == nil {
		t.Fatal("migration widened trust to a different local node")
	}
	if err := loaded.Validate(k); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(root, loaded, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatal("migration bypassed revision guard")
	}
	if _, err := Save(root, loaded, rev); err != nil {
		t.Fatal(err)
	}
	stored, err = os.ReadFile(path)
	if err != nil || bytes.Contains(stored, []byte(`"quic-ip"`)) {
		t.Fatal("next save did not persist H3 migration")
	}
}

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
		wantMode := mode
		if wantMode == "quic-ip" {
			wantMode = "http3-ip"
		}
		if err != nil || gotRevision != rev || string(cfg.Mode) != wantMode {
			t.Fatalf("load mode=%s %+v %s %v", mode, cfg, gotRevision, err)
		}
		if mode != "native" && cfg.Factory.Mode() != wgtransport.Mode(wantMode) {
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
func TestManagedProfileUsesConservativeQUICInitialPacketSize(t *testing.T) {
	local, _ := newProfile(t)
	peer, _ := newProfile(t)
	for _, mode := range []string{"quic-ip", "http3-ip"} {
		p := local
		p.Mode = mode
		p.AutoTrust = mode == "http3-ip"
		p.Peers = []ipn.TransportPeer{*peer.Identity}
		factory, err := p.Factory()
		if err != nil {
			t.Fatalf("mode=%s: %v", mode, err)
		}
		backend, err := factory.New(wgtransport.Host{Bind: conn.NewDefaultBind(), PeerAllowed: func([32]byte) bool { return true }, NodePublic: func() [32]byte { return [32]byte{1} }, NodeHandshake: func([32]byte, [32]byte, bool, []byte) (nodeauth.Handshake, error) { return nil, nil }})
		if err != nil {
			t.Fatalf("mode=%s: create backend: %v", mode, err)
		}
		got, ok := backend.(*quicbind.Backend).Snapshot()["initial_packet_size"]
		if !ok {
			t.Fatalf("mode=%s: missing initial_packet_size in snapshot", mode)
		}
		if got != uint16(1200) {
			t.Fatalf("mode=%s: initial_packet_size=%v, want 1200", mode, got)
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
	manualPins := false
	p, err = Apply(p, ipn.TransportControlRequest{Action: "mode", Mode: "http3-ip", AutoTrust: &manualPins}, k)
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
