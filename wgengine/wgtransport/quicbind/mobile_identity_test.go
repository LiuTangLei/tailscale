// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"tailscale.com/wgengine/wgtransport"
	"testing"
)

func TestEmbeddedIdentityWithoutFilesOrEnvironment(t *testing.T) {
	pair := newTestPair(t, "http3-udp")
	f := pair.backends[0].factory
	c := f.cfg
	c.Certificate, c.PrivateKey = "", ""
	memory, err := NewFactoryWithCertificate(c, f.cert)
	if err != nil {
		t.Fatal(err)
	}
	if memory.Mode() != wgtransport.HTTP3IP || memory.local != f.local {
		t.Fatal("in-memory configuration changed identity or mode")
	}
	if &memory.cert.Certificate[0][0] == &f.cert.Certificate[0][0] {
		t.Fatal("certificate bytes were not copied")
	}
	c.Certificate = "ambiguous.pem"
	if _, err := NewFactoryWithCertificate(c, f.cert); err == nil {
		t.Fatal("accepted ambiguous identity sources")
	}
}
