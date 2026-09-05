// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/tun/tuntest"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/quicip"
)

func TestNativeIPUsesTailscaleInboundACL(t *testing.T) {
	pair := newTestPair(t, "udp", func(c *Config) { c.Version = 2; c.Payload = "ip" })
	ips := [2]netip.Addr{netip.MustParseAddr("10.88.0.1"), netip.MustParseAddr("10.88.0.2")}
	var tuns [2]*tuntest.ChannelTUN
	var wrappers [2]*tstun.Wrapper
	var inspected [2]atomic.Int64
	for i := range 2 {
		i := i
		tuns[i] = tuntest.NewChannelTUN()
		wrappers[i] = tstun.Wrap(t.Logf, tuns[i].TUN(), new(usermetric.Registry), eventbustest.NewBus(t))
		wrappers[i].SetFilter(filter.NewAllowAllForTest(t.Logf))
		wrappers[i].PreFilterPacketInboundFromWireGuard = func(*packet.Parsed, *tstun.Wrapper) filter.Response { inspected[i].Add(1); return filter.Accept }
		wrappers[i].Start()
		d, err := quicip.New(wrappers[i], pair.backends[i].Bind())
		if err != nil {
			t.Fatal(err)
		}
		remote := pair.keys[i^1].Public().Raw32()
		d.SetLocalIdentity(pair.keys[i].Public().Raw32())
		d.SetPolicy(quicip.Policy{PeerAllowed: func(k [32]byte) bool { return k == remote }, SourceAllowed: func(k [32]byte, src netip.Addr) bool { return k == remote && src == ips[i^1] }})
		d.SetRouteFunc(func(dst netip.Addr) ([32]byte, bool) { return remote, dst == ips[i^1] })
		pair.backends[i].host.SessionChanged = d.SessionChanged
		t.Cleanup(d.Close)
		if err := d.Up(); err != nil {
			t.Fatal(err)
		}
		pair.bases[i^1].setRemote(fmt.Sprintf("127.0.0.1:%d", pair.backends[i].active.Load().port))
	}
	msg := tuntest.Ping(ips[1], ips[0])
	send := func() {
		t.Helper()
		select {
		case tuns[0].Outbound <- msg:
		case <-time.After(3 * time.Second):
			t.Fatal("TUN send blocked")
		}
	}
	send()
	select {
	case got := <-tuns[1].Inbound:
		if !bytes.Equal(msg, got) {
			t.Fatal("payload changed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("allow-all ACL did not deliver")
	}
	// A live filter update must still run after native QUIC source validation.
	wrappers[1].SetFilter(filter.NewAllowNone(t.Logf, nil))
	before := inspected[1].Load()
	send()
	deadline := time.Now().Add(2 * time.Second)
	for inspected[1].Load() == before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if inspected[1].Load() == before {
		t.Fatal("packet bypassed the existing Tailscale inbound filter path")
	}
	select {
	case <-tuns[1].Inbound:
		t.Fatal("deny-all ACL was bypassed by QUIC injection")
	case <-time.After(20 * time.Millisecond):
	}
	wrappers[1].SetFilter(filter.NewAllowAllForTest(t.Logf))
	send()
	select {
	case <-tuns[1].Inbound:
	case <-time.After(2 * time.Second):
		t.Fatal("live ACL restore did not take effect")
	}
}
