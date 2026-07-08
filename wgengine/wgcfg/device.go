// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/LiuTangLei/wireguard-go/device"
	"github.com/LiuTangLei/wireguard-go/tun"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
)

var (
	amneziaJC   = envknob.RegisterInt("TS_AMNEZIA_JC")
	amneziaJMin = envknob.RegisterInt("TS_AMNEZIA_JMIN")
	amneziaJMax = envknob.RegisterInt("TS_AMNEZIA_JMAX")
	amneziaS1   = envknob.RegisterInt("TS_AMNEZIA_S1")
	amneziaS2   = envknob.RegisterInt("TS_AMNEZIA_S2")
	amneziaS3   = envknob.RegisterInt("TS_AMNEZIA_S3")
	amneziaS4   = envknob.RegisterInt("TS_AMNEZIA_S4")
	amneziaI1   = envknob.RegisterString("TS_AMNEZIA_I1")
	amneziaI2   = envknob.RegisterString("TS_AMNEZIA_I2")
	amneziaI3   = envknob.RegisterString("TS_AMNEZIA_I3")
	amneziaI4   = envknob.RegisterString("TS_AMNEZIA_I4")
	amneziaI5   = envknob.RegisterString("TS_AMNEZIA_I5")
	amneziaH1   = envknob.RegisterInt("TS_AMNEZIA_H1")
	amneziaH2   = envknob.RegisterInt("TS_AMNEZIA_H2")
	amneziaH3   = envknob.RegisterInt("TS_AMNEZIA_H3")
	amneziaH4   = envknob.RegisterInt("TS_AMNEZIA_H4")
)

// NewDevice returns a wireguard-go Device configured for Tailscale use.
func NewDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	return device.NewDevice(tunDev, bind, logger)
}

// ReconfigDevice replaces the existing device configuration with cfg.
//
// Instead of using the UAPI text protocol, it uses the wireguard-go direct API
// to install a [device.PeerLookupFunc] callback that creates peers on demand.
//
// The caller is responsible for:
//   - calling [device.Device.SetPrivateKey] when the key changes
//   - installing a [device.PeerByIPPacketFunc] on the device for outbound
//     packet routing (e.g. via [tailscale.com/wgengine.Engine.SetPeerByIPPacketFunc])
func ReconfigDevice(d *device.Device, cfg *Config, logf logger.Logf) (err error) {
	defer func() {
		if err != nil {
			logf("wgcfg.Reconfig failed: %v", err)
		}
	}()

	if err := applyAmneziaConfig(d, cfg); err != nil {
		return err
	}

	// Build peer map: public key → allowed IPs.
	peers := make(map[device.NoisePublicKey][]netip.Prefix, len(cfg.Peers))
	for _, p := range cfg.Peers {
		peers[p.PublicKey.Raw32()] = p.AllowedIPs
	}

	// Remove peers not in the new config.
	d.RemoveMatchingPeers(func(pk device.NoisePublicKey) bool {
		_, exists := peers[pk]
		return !exists
	})

	// Update AllowedIPs on any already-active peers whose config may have
	// changed. Peers that don't exist yet will get the correct AllowedIPs
	// from PeerLookupFunc when they are lazily created.
	for pk, allowedIPs := range peers {
		if peer, ok := d.LookupActivePeer(pk); ok {
			peer.SetAllowedIPs(allowedIPs)
		}
	}

	// Install callback for lazy peer creation (incoming packets).
	bind := d.Bind()
	d.SetPeerLookupFunc(func(pubk device.NoisePublicKey) (_ *device.NewPeerConfig, ok bool) {
		allowedIPs, ok := peers[pubk]
		if !ok {
			return nil, false
		}
		ep, err := bind.ParseEndpoint(fmt.Sprintf("%x", pubk[:]))
		if err != nil {
			logf("wgcfg: failed to parse endpoint for peer %x: %v", pubk[:8], err)
			return nil, false
		}
		return &device.NewPeerConfig{
			AllowedIPs: allowedIPs,
			Endpoint:   ep,
		}, true
	})

	// RemoveMatchingPeers _again_, now that SetPeerLookupFunc is installed,
	// lest any removed peers got re-created before the new SetPeerLookupFunc
	// func was installed.
	d.RemoveMatchingPeers(func(pk device.NoisePublicKey) bool {
		_, exists := peers[pk]
		return !exists
	})

	return nil
}

func applyAmneziaConfig(d *device.Device, cfg *Config) error {
	var buf bytes.Buffer
	set := func(key, value string) {
		fmt.Fprintf(&buf, "%s=%s\n", key, value)
	}
	setUint16 := func(key string, value uint16) {
		set(key, strconv.FormatUint(uint64(value), 10))
	}
	setMagicHeaderRange := func(key string, value ipn.MagicHeaderRange) {
		if value.Min == value.Max {
			set(key, strconv.FormatUint(uint64(value.Min), 10))
		} else {
			set(key, fmt.Sprintf("%d-%d", value.Min, value.Max))
		}
	}

	jc := cfg.AmneziaJC
	if jc == 0 {
		jc = uint16(amneziaJC())
	}
	if jc > 0 {
		setUint16("jc", jc)
	}

	jmin := cfg.AmneziaJMin
	if jmin == 0 {
		jmin = uint16(amneziaJMin())
	}
	if jmin > 0 {
		setUint16("jmin", jmin)
	}

	jmax := cfg.AmneziaJMax
	if jmax == 0 {
		jmax = uint16(amneziaJMax())
	}
	if jmax > 0 {
		setUint16("jmax", jmax)
	}

	s1 := cfg.AmneziaS1
	if s1 == 0 {
		s1 = uint16(amneziaS1())
	}
	if s1 > 0 {
		setUint16("s1", s1)
	}

	s2 := cfg.AmneziaS2
	if s2 == 0 {
		s2 = uint16(amneziaS2())
	}
	if s2 > 0 {
		setUint16("s2", s2)
	}

	s3 := cfg.AmneziaS3
	if s3 == 0 {
		s3 = uint16(amneziaS3())
	}
	if s3 > 0 {
		setUint16("s3", s3)
	}

	s4 := cfg.AmneziaS4
	if s4 == 0 {
		s4 = uint16(amneziaS4())
	}
	if s4 > 0 {
		setUint16("s4", s4)
	}

	i1 := cfg.AmneziaI1
	if i1 == "" {
		i1 = amneziaI1()
	}
	if i1 != "" {
		set("i1", i1)
	}

	i2 := cfg.AmneziaI2
	if i2 == "" {
		i2 = amneziaI2()
	}
	if i2 != "" {
		set("i2", i2)
	}

	i3 := cfg.AmneziaI3
	if i3 == "" {
		i3 = amneziaI3()
	}
	if i3 != "" {
		set("i3", i3)
	}

	i4 := cfg.AmneziaI4
	if i4 == "" {
		i4 = amneziaI4()
	}
	if i4 != "" {
		set("i4", i4)
	}

	i5 := cfg.AmneziaI5
	if i5 == "" {
		i5 = amneziaI5()
	}
	if i5 != "" {
		set("i5", i5)
	}

	h1 := cfg.AmneziaH1
	if h1.Min == 0 && h1.Max == 0 {
		if h1Val := uint32(amneziaH1()); h1Val > 0 {
			h1 = ipn.MagicHeaderRange{Min: h1Val, Max: h1Val}
		}
	}
	if h1.Min > 0 || h1.Max > 0 {
		setMagicHeaderRange("h1", h1)
	}

	h2 := cfg.AmneziaH2
	if h2.Min == 0 && h2.Max == 0 {
		if h2Val := uint32(amneziaH2()); h2Val > 0 {
			h2 = ipn.MagicHeaderRange{Min: h2Val, Max: h2Val}
		}
	}
	if h2.Min > 0 || h2.Max > 0 {
		setMagicHeaderRange("h2", h2)
	}

	h3 := cfg.AmneziaH3
	if h3.Min == 0 && h3.Max == 0 {
		if h3Val := uint32(amneziaH3()); h3Val > 0 {
			h3 = ipn.MagicHeaderRange{Min: h3Val, Max: h3Val}
		}
	}
	if h3.Min > 0 || h3.Max > 0 {
		setMagicHeaderRange("h3", h3)
	}

	h4 := cfg.AmneziaH4
	if h4.Min == 0 && h4.Max == 0 {
		if h4Val := uint32(amneziaH4()); h4Val > 0 {
			h4 = ipn.MagicHeaderRange{Min: h4Val, Max: h4Val}
		}
	}
	if h4.Min > 0 || h4.Max > 0 {
		setMagicHeaderRange("h4", h4)
	}

	if buf.Len() == 0 {
		return nil
	}
	buf.WriteByte('\n')
	return d.IpcSetOperation(&buf)
}
