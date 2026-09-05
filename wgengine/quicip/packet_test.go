// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicip

import (
	"encoding/binary"
	"github.com/LiuTangLei/wireguard-go/tun/tuntest"
	"net/netip"
	"testing"
)

func TestParseIP(t *testing.T) {
	a, b := netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2")
	v4 := tuntest.Ping(b, a)
	s, d, err := ParseIP(v4)
	if err != nil || s != a || d != b {
		t.Fatalf("IPv4: %v %v %v", s, d, err)
	}
	a6, b6 := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	v6 := make([]byte, 48)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], 8)
	copy(v6[8:24], a6.AsSlice())
	copy(v6[24:40], b6.AsSlice())
	s, d, err = ParseIP(v6)
	if err != nil || s != a6 || d != b6 {
		t.Fatalf("IPv6: %v %v %v", s, d, err)
	}
	for _, bad := range [][]byte{nil, {0x40}, v4[:19], append(append([]byte(nil), v4...), 0), v6[:47], append(append([]byte(nil), v6...), 0)} {
		if _, _, err := ParseIP(bad); err == nil {
			t.Fatalf("accepted malformed len=%d", len(bad))
		}
	}
	mapped := append([]byte(nil), v6...)
	copy(mapped[8:24], netip.MustParseAddr("::ffff:10.1.0.1").AsSlice())
	if _, _, err := ParseIP(mapped); err == nil {
		t.Fatal("mapped IPv6 source bypass")
	}
	badIHL := append([]byte(nil), v4...)
	badIHL[0] = 0x44
	if _, _, err := ParseIP(badIHL); err == nil {
		t.Fatal("invalid IPv4 IHL")
	}
}
func FuzzParseIP(f *testing.F) {
	f.Add(tuntest.Ping(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")))
	f.Add([]byte{0x60})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, d, err := ParseIP(b)
		if err == nil && (!s.IsValid() || !d.IsValid()) {
			t.Fatal("accepted invalid address")
		}
	})
}
func BenchmarkParseIP(b *testing.B) {
	pkt := tuntest.Ping(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ParseIP(pkt); err != nil {
			b.Fatal(err)
		}
	}
}
