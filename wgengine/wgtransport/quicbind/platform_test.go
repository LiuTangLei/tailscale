// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import "testing"

func TestIndependentSocketPlatformPolicy(t *testing.T) {
	for _, os := range []string{"ios", "android", "js"} {
		if supportsIndependentUDP(os) {
			t.Errorf("unprotected extra socket permitted on %s", os)
		}
	}
	for _, os := range []string{"linux", "darwin", "windows", "freebsd", "openbsd"} {
		if !supportsIndependentUDP(os) {
			t.Errorf("host-protected socket unexpectedly disabled on %s", os)
		}
	}
}

func TestInMemoryIdentityForEmbedding(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock")
	original := pair.backends[0].factory
	c := original.cfg
	c.Certificate, c.PrivateKey = "", ""
	f, err := NewFactoryWithCertificate(c, original.cert)
	if err != nil {
		t.Fatal(err)
	}
	if f.protocol() != "h3" || f.local != original.local || len(f.peers) != 1 {
		t.Fatal("embedded identity changed protocol or peer binding")
	}
	if &f.cert.Certificate[0][0] == &original.cert.Certificate[0][0] {
		t.Fatal("caller can mutate retained certificate bytes")
	}
}
