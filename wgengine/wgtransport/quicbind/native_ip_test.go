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
	"tailscale.com/wgengine/quicip"
)

func TestNativeIPDataPlaneActualQUIC(t *testing.T) {
	for _, mode := range []string{"udp", "magicsock", "http3-udp", "http3-magicsock"} {
		t.Run(mode, func(t *testing.T) {
			pair := newTestPair(t, mode, func(c *Config) { c.Version = 2; c.Payload = "ip" })
			var devices [2]*quicip.Device
			var tuns [2]*tuntest.ChannelTUN
			var admitted [2]atomic.Bool
			var sourceAllowed [2]atomic.Bool
			ips := [2]netip.Addr{netip.MustParseAddr("10.88.0.1"), netip.MustParseAddr("10.88.0.2")}
			for i := range 2 {
				i := i
				admitted[i].Store(true)
				sourceAllowed[i].Store(true)
				tuns[i] = tuntest.NewChannelTUN()
				d, err := quicip.New(tuns[i].TUN(), pair.backends[i].Bind())
				if err != nil {
					t.Fatal(err)
				}
				devices[i] = d
				d.SetLocalIdentity(pair.keys[i].Public().Raw32())
				remoteKey := pair.keys[i^1].Public().Raw32()
				d.SetPolicy(quicip.Policy{
					PeerAllowed: func(k [32]byte) bool { return admitted[i].Load() && k == remoteKey },
					SourceAllowed: func(k [32]byte, src netip.Addr) bool {
						return sourceAllowed[i].Load() && k == remoteKey && src == ips[i^1]
					},
				})
				d.SetRouteFunc(func(ip netip.Addr) ([32]byte, bool) { return remoteKey, ip == ips[i^1] })
				pair.backends[i].host.SessionChanged = d.SessionChanged
				t.Cleanup(d.Close)
				if err := d.Up(); err != nil {
					t.Fatal(err)
				}
				port := pair.backends[i].active.Load().port
				pair.bases[i^1].setRemote(fmt.Sprintf("127.0.0.1:%d", port))
			}
			send := func(from int, src netip.Addr) {
				t.Helper()
				msg := tuntest.Ping(ips[from^1], src)
				select {
				case tuns[from].Outbound <- msg:
				case <-time.After(3 * time.Second):
					t.Fatal("TUN blocked")
				}
			}
			for i := range 2 {
				send(i, ips[i])
				select {
				case got := <-tuns[i^1].Inbound:
					if !bytes.Equal(got, tuntest.Ping(ips[i^1], ips[i])) {
						t.Fatal("IP payload changed")
					}
				case <-time.After(6 * time.Second):
					t.Fatal("native IP did not cross QUIC")
				}
				st, ok := devices[i].PeerStatus(pair.keys[i^1].Public().Raw32())
				if !ok || st.LastEstablished.IsZero() {
					t.Fatalf("missing real TLS session timestamp: %+v", st)
				}
			}
			// A legitimate pinned TLS peer sending someone else's IP must be rejected
			// before TUN.Write even though the QUIC session itself remains authenticated.
			before := devices[1].Counters().SourceDenied.Load()
			send(0, netip.MustParseAddr("10.88.0.99"))
			deadline := time.Now().Add(2 * time.Second)
			for devices[1].Counters().SourceDenied.Load() == before && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if devices[1].Counters().SourceDenied.Load() == before {
				t.Fatal("spoofed source was not rejected")
			}
			select {
			case <-tuns[1].Inbound:
				t.Fatal("spoofed source reached TUN")
			default:
			}
			// Revoking a source route applies to a live session without a new handshake.
			sourceAllowed[1].Store(false)
			send(0, ips[0])
			time.Sleep(20 * time.Millisecond)
			select {
			case <-tuns[1].Inbound:
				t.Fatal("revoked route reached TUN")
			default:
			}
			sourceAllowed[1].Store(true)
			admitted[1].Store(false)
			send(0, ips[0])
			deadline = time.Now().Add(2 * time.Second)
			for devices[1].Counters().PeerDenied.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if devices[1].Counters().PeerDenied.Load() == 0 {
				t.Fatal("revoked peer admission not checked on live data")
			}
			select {
			case <-tuns[1].Inbound:
				t.Fatal("revoked peer reached TUN")
			default:
			}
			for _, b := range pair.backends {
				st := b.factory.Snapshot()
				if st["alpn"] != b.factory.protocol() || st["wireguard_encryption"] != false || st["payload"] != "ip" {
					t.Fatalf("not native IP: %+v", st)
				}
			}
		})
	}
}

func TestNativeIPRequiresLiveAuthorization(t *testing.T) {
	pair := newTestPair(t, "udp", func(c *Config) { c.Version = 2; c.Payload = "ip" })
	host := pair.backends[0].host
	host.PeerAllowed = nil
	if _, err := pair.backends[0].factory.New(host); err == nil {
		t.Fatal("native IP accepted pins without live admission")
	}
}

func TestNativeIPVersionAndALPNSeparation(t *testing.T) {
	pair := newTestPair(t, "udp")
	c := pair.backends[0].factory.cfg
	c.Version = 1
	c.Payload = "ip"
	if _, err := NewFactory(c); err == nil {
		t.Fatal("legacy config silently switched plaintext format")
	}
	c.Version = 2
	c.Payload = "wireguard"
	if _, err := NewFactory(c); err == nil {
		t.Fatal("version 2 silently accepted WireGuard")
	}
}
