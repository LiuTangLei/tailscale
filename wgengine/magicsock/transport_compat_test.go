// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package magicsock

import (
	"errors"
	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/disco"
	"tailscale.com/ipn"
	"testing"
)

func TestAWG31ConfigCapabilityGate(t *testing.T) {
	p := ipn.AmneziaWGPrefs{RandomTrailers: true}
	for _, version := range []uint8{0, 2, 3, 4} {
		req := &disco.AmneziaWGConfigRequest{MaxConfigVersion: version}
		got := amneziaWGConfigRequestCompatible(req, p)
		if got != (version >= disco.AmneziaWGConfigVersionV31) {
			t.Errorf("version %d accepted=%v", version, got)
		}
	}
	req := &disco.AmneziaWGConfigRequest{MaxConfigVersion: disco.AmneziaWGConfigVersionV31}
	if !amneziaWGConfigRequestCompatible(req, ipn.AmneziaWGPrefs{}) {
		t.Fatal("new client cannot request legacy config")
	}
}

func TestUnknownTransportEndpointIsAnError(t *testing.T) {
	c := newTestConn(t)
	b := conn.NewDefaultBind()
	ep, err := b.ParseEndpoint("127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send([][]byte{{1, 2, 3}}, ep, 0); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("send=%v", err)
	}
}
