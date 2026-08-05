// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/LiuTangLei/wireguard-go/device"
	"github.com/LiuTangLei/wireguard-go/tun"
	"tailscale.com/ipn"
	"tailscale.com/types/key"
)

func TestApplyAmneziaConfigV3ThenV2(t *testing.T) {
	dev := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "test"))
	defer dev.Close()

	v3 := ipn.AmneziaWGPrefs{
		JC:                     5,
		JMin:                   500,
		JMax:                   1000,
		S1:                     15,
		S2:                     18,
		S3:                     20,
		S4:                     25,
		H1:                     ipn.MagicHeaderRange{Min: 123456, Max: 123500},
		H2:                     ipn.MagicHeaderRange{Min: 67543, Max: 67550},
		H3:                     ipn.MagicHeaderRange{Min: 123123, Max: 123200},
		H4:                     ipn.MagicHeaderRange{Min: 32345, Max: 32350},
		HeaderProtectionKey:    strings.Repeat("42", device.HeaderCipherKeySize),
		ContentPaddingAddition: ipn.MagicHeaderRange{Min: 5, Max: 31},
		RekeyAfterTime:         ipn.MagicHeaderRange{Min: 120, Max: 180},
		RekeyTimeout:           ipn.MagicHeaderRange{Min: 5, Max: 7},
		RejectAfterTime:        ipn.MagicHeaderRange{Min: 180, Max: 240},
		KeepaliveTimeout:       ipn.MagicHeaderRange{Min: 10, Max: 15},
		MaxHandshakeAttempts:   ipn.MagicHeaderRange{Min: 8, Max: 12},
	}
	if err := ApplyAmneziaConfig(dev, v3); err != nil {
		t.Fatalf("applying AWG v3 config: %v", err)
	}
	gotV3, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"jc=5\n",
		"s4=25\n",
		"h1=123456-123500\n",
		"header_protection_key=" + strings.Repeat("42", device.HeaderCipherKeySize) + "\n",
		"content_padding_addition=5-31\n",
		"rekey_after_time=120-180\n",
		"max_handshake_attempts=8-12\n",
	} {
		if !strings.Contains(gotV3, line) {
			t.Errorf("AWG v3 IpcGet missing %q in:\n%s", line, gotV3)
		}
	}

	// A v2 profile intentionally omits every v3-only parameter. Applying it to
	// the same device must clear the old v3 state while retaining v2 behavior.
	v2 := ipn.AmneziaWGPrefs{
		JC:   4,
		JMin: 40,
		JMax: 70,
		S1:   5,
		S2:   7,
		S3:   9,
		S4:   11,
		I1:   "<r 8>",
		H1:   ipn.MagicHeaderRange{Min: 1001, Max: 1001},
		H2:   ipn.MagicHeaderRange{Min: 1002, Max: 1002},
		H3:   ipn.MagicHeaderRange{Min: 1003, Max: 1003},
		H4:   ipn.MagicHeaderRange{Min: 1004, Max: 1004},
	}
	if err := ApplyAmneziaConfig(dev, v2); err != nil {
		t.Fatalf("applying AWG v2 config after v3: %v", err)
	}
	gotV2, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"jc=4\n", "s1=5\n", "h1=1001\n", "i1=<r 8>\n"} {
		if !strings.Contains(gotV2, line) {
			t.Errorf("AWG v2 IpcGet missing %q in:\n%s", line, gotV2)
		}
	}
	for _, stale := range []string{
		"header_protection_key=",
		"content_padding_addition=",
		"rekey_after_time=",
		"rekey_timeout=",
		"reject_after_time=",
		"keepalive_timeout=",
		"max_handshake_attempts=",
	} {
		if strings.Contains(gotV2, stale) {
			t.Errorf("AWG v2 config retained stale v3 field %q in:\n%s", stale, gotV2)
		}
	}
}

func TestApplyAmneziaConfigRejectsShortHeaderPadding(t *testing.T) {
	dev := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "test"))
	defer dev.Close()

	err := ApplyAmneziaConfig(dev, ipn.AmneziaWGPrefs{
		S1:                  11,
		S2:                  12,
		S3:                  12,
		S4:                  12,
		HeaderProtectionKey: strings.Repeat("42", device.HeaderCipherKeySize),
	})
	if err == nil || !strings.Contains(err.Error(), "S1 must be at least 12") {
		t.Fatalf("ApplyAmneziaConfig error = %v, want S1 padding validation", err)
	}
}

func TestEffectiveAmneziaConfigIncludesEnvironment(t *testing.T) {
	oldJC, oldI1, oldH1 := amneziaJC, amneziaI1, amneziaH1
	amneziaJC = func() int { return 7 }
	amneziaI1 = func() string { return "<b 0xc0><r 32>" }
	amneziaH1 = func() int { return 100001 }
	t.Cleanup(func() {
		amneziaJC, amneziaI1, amneziaH1 = oldJC, oldI1, oldH1
	})

	got, err := EffectiveAmneziaConfig(ipn.AmneziaWGPrefs{})
	if err != nil {
		t.Fatal(err)
	}
	if got.JC != 7 || got.I1 != "<b 0xc0><r 32>" || got.H1 != (ipn.MagicHeaderRange{Min: 100001, Max: 100001}) {
		t.Fatalf("effective environment config = %#v", got)
	}
	uapi, err := amneziaUAPIConfig(ipn.AmneziaWGPrefs{})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"jc=7\n", "i1=<b 0xc0><r 32>\n", "h1=100001\n"} {
		if !strings.Contains(uapi, line) {
			t.Errorf("UAPI missing %q in:\n%s", line, uapi)
		}
	}
}

func TestEffectiveAmneziaConfigRejectsInvalidEnvironment(t *testing.T) {
	oldJC := amneziaJC
	t.Cleanup(func() { amneziaJC = oldJC })

	for _, value := range []int{-1, 1 << 16} {
		amneziaJC = func() int { return value }
		_, err := EffectiveAmneziaConfig(ipn.AmneziaWGPrefs{})
		if err == nil || !strings.Contains(err.Error(), "TS_AMNEZIA_JC must be between") {
			t.Fatalf("TS_AMNEZIA_JC=%d error = %v", value, err)
		}
	}
}

func TestAmneziaUAPIConfigRejectsLineInjection(t *testing.T) {
	_, err := amneziaUAPIConfig(ipn.AmneziaWGPrefs{I1: "<b 0xc0>\nprivate_key=00"})
	if err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("amneziaUAPIConfig injection error = %v", err)
	}
}

func TestNewPeerLookupFunc(t *testing.T) {
	k1, _ := newK()

	k2, _ := newK()
	ip2 := netip.MustParsePrefix("10.0.0.2/32")

	k3, _ := newK()

	dev := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "test"))
	defer dev.Close()

	// peers is the live per-peer config source, standing in for what
	// LocalBackend provides via wgengine.Engine.SetPeerConfigFunc.
	peers := map[device.NoisePublicKey][]netip.Prefix{
		k2.Raw32(): {ip2},
	}
	dev.SetPeerLookupFunc(NewPeerLookupFunc(dev.Bind(), t.Logf, func(pubk device.NoisePublicKey) ([]netip.Prefix, bool) {
		ips, ok := peers[pubk]
		return ips, ok
	}))

	t.Run("lazy-creation", func(t *testing.T) {
		// A peer known to the config source should be creatable on
		// demand via LookupPeer.
		if p := dev.LookupPeer(k2.Raw32()); p == nil {
			t.Fatal("expected peer k2 to exist via LookupPeer")
		}
		// An unknown peer should not be found.
		if p := dev.LookupPeer(k3.Raw32()); p != nil {
			t.Fatal("expected unknown peer k3 to not exist")
		}
	})

	t.Run("remove-peer", func(t *testing.T) {
		delete(peers, k2.Raw32())
		dev.RemoveMatchingPeers(func(pk device.NoisePublicKey) bool {
			_, ok := peers[pk]
			return !ok
		})
		if p := dev.LookupPeer(k2.Raw32()); p != nil {
			t.Fatal("expected peer k2 to not exist after removal")
		}
	})

	t.Run("self-key-not-peer", func(t *testing.T) {
		// The device's own key should not be a peer.
		if p := dev.LookupPeer(k1.Raw32()); p != nil {
			t.Fatal("expected own key to not be a peer")
		}
	})
}

func newK() (key.NodePublic, key.NodePrivate) {
	k := key.NewNode()
	return k.Public(), k
}

// TODO: replace with a loopback tunnel
type nilTun struct {
	events chan tun.Event
	closed chan struct{}
}

func newNilTun() tun.Device {
	return &nilTun{
		events: make(chan tun.Event),
		closed: make(chan struct{}),
	}
}

func (t *nilTun) File() *os.File           { return nil }
func (t *nilTun) Flush() error             { return nil }
func (t *nilTun) MTU() (int, error)        { return 1420, nil }
func (t *nilTun) Name() (string, error)    { return "niltun", nil }
func (t *nilTun) Events() <-chan tun.Event { return t.events }

func (t *nilTun) Read(data [][]byte, sizes []int, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Write(data [][]byte, offset int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *nilTun) Close() error {
	close(t.events)
	close(t.closed)
	return nil
}

func (t *nilTun) BatchSize() int { return 1 }

// A noopBind is a conn.Bind that does no actual binding work.
type noopBind struct{}

func (noopBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return nil, 1, nil
}
func (noopBind) Close() error                                        { return nil }
func (noopBind) SetMark(mark uint32) error                           { return nil }
func (noopBind) Send(b [][]byte, ep conn.Endpoint, offset int) error { return nil }
func (noopBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return dummyEndpoint(s), nil
}
func (noopBind) BatchSize() int { return 1 }

// A dummyEndpoint is a string holding the endpoint destination.
type dummyEndpoint string

func (e dummyEndpoint) ClearSrc()           {}
func (e dummyEndpoint) SrcToString() string { return "" }
func (e dummyEndpoint) DstToString() string { return string(e) }
func (e dummyEndpoint) DstToBytes() []byte  { return nil }
func (e dummyEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (dummyEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
