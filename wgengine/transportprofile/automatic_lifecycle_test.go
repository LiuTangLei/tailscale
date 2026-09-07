// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package transportprofile

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
)

func profileWithValidity(t *testing.T, p Profile, from, to time.Time) Profile {
	t.Helper()
	cert, err := tls.X509KeyPair([]byte(p.Certificate), []byte(p.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotBefore, leaf.NotAfter = from, to
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	p.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return p
}
func TestAutomaticIdentityExpiryAndCorruption(t *testing.T) {
	now := time.Now()
	for _, kind := range []string{"expired-auto", "expired-manual", "future-auto", "expired-bad-pin", "bad-private-key"} {
		t.Run(kind, func(t *testing.T) {
			p, k := newProfile(t)
			remote, _ := newProfile(t)
			p, err := Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: remote.Identity}, k)
			if err != nil {
				t.Fatal(err)
			}
			p.Mode = "http3-ip"
			p.AutoTrust = kind != "expired-manual"
			p.Server = true
			if kind == "future-auto" {
				p = profileWithValidity(t, p, now.Add(time.Hour), now.Add(2*time.Hour))
			} else {
				p = profileWithValidity(t, p, now.Add(-2*time.Hour), now.Add(-time.Hour))
			}
			if kind == "expired-bad-pin" {
				card := *p.Identity
				card.SPKISHA256 = "corrupt"
				p.Identity = &card
			}
			if kind == "bad-private-key" {
				p.PrivateKey = remote.PrivateKey
			}
			root := t.TempDir()
			rev, err := Save(root, p, "0")
			if err != nil {
				t.Fatal(err)
			}
			cfg, afterRev, err := LoadForStart(root)
			after, diskRev, readErr := Read(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if kind == "expired-auto" {
				if err != nil || cfg.Factory == nil || afterRev == rev || afterRev != diskRev || !after.AutoTrust || !after.Server {
					t.Fatalf("renewal: %+v %v", cfg, err)
				}
				if after.LocalKey != p.LocalKey || len(after.Peers) != 1 {
					t.Fatal("renewal mutated node identity or pins")
				}
				if _, err := after.certificate(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					t.Fatal("malformed/manual/future identity renewed silently")
				}
				if diskRev != rev || after.PrivateKey != p.PrivateKey || after.Certificate != p.Certificate {
					t.Fatal("failed startup changed stored identity")
				}
			}
		})
	}
}
func TestAutoIdentityKeyRefreshDoesNotMutateInput(t *testing.T) {
	p, k := newProfile(t)
	p.Mode = "http3-ip"
	p.AutoTrust = true
	oldCard := *p.Identity
	oldPrivate := p.PrivateKey
	newKey := key.NewNode().Public().String()
	changed, err := NewIdentity(p, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if *p.Identity != oldCard || p.LocalKey != oldCard.PublicKey {
		t.Fatal("input profile was mutated")
	}
	if changed.Identity.PublicKey == oldCard.PublicKey || changed.PrivateKey != oldPrivate {
		t.Fatal("node key refresh rotated valid TLS identity")
	}
	p.Certificate = "bad-pem"
	if _, err := NewIdentity(p, newKey); err == nil {
		t.Fatal("corrupt certificate silently regenerated on key rotation")
	}
	if *p.Identity != oldCard {
		t.Fatal("failed update changed input")
	}
	_ = k
}
func TestOldManualH3ReadKeepsPinnedAuthentication(t *testing.T) {
	p, k := newProfile(t)
	peer, _ := newProfile(t)
	p, err := Apply(p, ipn.TransportControlRequest{Action: "add-peer", Peer: peer.Identity}, k)
	if err != nil {
		t.Fatal(err)
	}
	no := false
	p, err = Apply(p, ipn.TransportControlRequest{Action: "mode", Mode: "http3-ip", AutoTrust: &no}, k)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	rev, err := Save(root, p, "0")
	if err != nil {
		t.Fatal(err)
	}
	cfg, after, err := LoadForStart(root)
	if err != nil || cfg.Factory == nil || after != rev {
		t.Fatal(err)
	}
	loaded, _, err := Read(root)
	if err != nil || loaded.AutoTrust || loaded.Public(rev).Authentication != "pinned-key" {
		t.Fatal("old profile changed authentication")
	}
}
