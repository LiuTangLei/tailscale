// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"bytes"
	"encoding/hex"
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

	amneziaHeaderProtectionKey    = envknob.RegisterString("TS_AMNEZIA_HEADER_PROTECTION_KEY")
	amneziaContentPaddingAddition = envknob.RegisterString("TS_AMNEZIA_CONTENT_PADDING_ADDITION")
	amneziaRekeyAfterTime         = envknob.RegisterString("TS_AMNEZIA_REKEY_AFTER_TIME")
	amneziaRekeyTimeout           = envknob.RegisterString("TS_AMNEZIA_REKEY_TIMEOUT")
	amneziaRejectAfterTime        = envknob.RegisterString("TS_AMNEZIA_REJECT_AFTER_TIME")
	amneziaKeepaliveTimeout       = envknob.RegisterString("TS_AMNEZIA_KEEPALIVE_TIMEOUT")
	amneziaMaxHandshakeAttempts   = envknob.RegisterString("TS_AMNEZIA_MAX_HANDSHAKE_ATTEMPTS")
)

// NewDevice returns a wireguard-go Device configured for Tailscale use.
func NewDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	return device.NewDevice(tunDev, bind, logger, getDeviceOptions()...)
}

// NewPeerLookupFunc returns a [device.PeerLookupFunc] that lazily
// creates peers using allowedIPs as the source of each peer's allowed
// IPs. The peer's endpoint is derived from its public key via bind.
func NewPeerLookupFunc(bind conn.Bind, logf logger.Logf, allowedIPs func(device.NoisePublicKey) ([]netip.Prefix, bool)) device.PeerLookupFunc {
	return func(pubk device.NoisePublicKey) (_ *device.NewPeerConfig, ok bool) {
		ips, ok := allowedIPs(pubk)
		if !ok {
			return nil, false
		}
		ep, err := bind.ParseEndpoint(fmt.Sprintf("%x", pubk[:]))
		if err != nil {
			logf("wgcfg: failed to parse endpoint for peer %x: %v", pubk[:8], err)
			return nil, false
		}
		return &device.NewPeerConfig{
			AllowedIPs: ips,
			Endpoint:   ep,
		}, true
	}
}

// ApplyAmneziaConfig applies all device-wide AWG settings through wireguard-go's
// UAPI. Every setting is emitted, including zero values, so changing from an
// AWG v3 profile to an AWG v2 (or standard WireGuard) profile cannot retain
// stale v3-only state in a long-running tailscaled process.
func ApplyAmneziaConfig(d *device.Device, prefs ipn.AmneziaWGPrefs) error {
	config, err := amneziaUAPIConfig(prefs)
	if err != nil {
		return err
	}
	if err := d.IpcSetOperation(bytes.NewBufferString(config)); err != nil {
		return fmt.Errorf("apply AmneziaWG config: %w", err)
	}
	return nil
}

// EffectiveAmneziaConfig resolves the legacy TS_AMNEZIA_* environment knobs
// into prefs and validates the exact configuration that will reach the device.
// It is also used by the sync provider so peers see the node's actual runtime
// profile rather than only the persisted portion of it.
func EffectiveAmneziaConfig(prefs ipn.AmneziaWGPrefs) (ipn.AmneziaWGPrefs, error) {
	resolveUint16 := func(name string, value uint16, envValue func() int) (uint16, error) {
		if value != 0 {
			return value, nil
		}
		configured := envValue()
		if configured < 0 || configured > 1<<16-1 {
			return 0, fmt.Errorf("%s must be between 0 and %d, got %d", name, 1<<16-1, configured)
		}
		return uint16(configured), nil
	}
	resolveHeader := func(name string, value ipn.MagicHeaderRange, envValue func() int) (ipn.MagicHeaderRange, error) {
		if !value.IsZero() {
			return value, nil
		}
		configured := envValue()
		if configured < 0 || uint64(configured) > 1<<32-1 {
			return ipn.MagicHeaderRange{}, fmt.Errorf("%s must be between 0 and %d, got %d", name, uint64(1<<32-1), configured)
		}
		if configured == 0 {
			return value, nil
		}
		return ipn.MagicHeaderRange{Min: uint32(configured), Max: uint32(configured)}, nil
	}
	resolveRange := func(name string, value ipn.MagicHeaderRange, envValue func() string) (ipn.MagicHeaderRange, error) {
		if !value.IsZero() {
			return value, nil
		}
		env := envValue()
		if env == "" {
			return value, nil
		}
		resolved, err := ipn.ParseMagicHeaderRange(env)
		if err != nil {
			return ipn.MagicHeaderRange{}, fmt.Errorf("invalid %s environment value %q: %w", name, env, err)
		}
		return resolved, nil
	}

	var err error
	for _, field := range []struct {
		name     string
		value    *uint16
		envValue func() int
	}{
		{"TS_AMNEZIA_JC", &prefs.JC, amneziaJC},
		{"TS_AMNEZIA_JMIN", &prefs.JMin, amneziaJMin},
		{"TS_AMNEZIA_JMAX", &prefs.JMax, amneziaJMax},
		{"TS_AMNEZIA_S1", &prefs.S1, amneziaS1},
		{"TS_AMNEZIA_S2", &prefs.S2, amneziaS2},
		{"TS_AMNEZIA_S3", &prefs.S3, amneziaS3},
		{"TS_AMNEZIA_S4", &prefs.S4, amneziaS4},
	} {
		*field.value, err = resolveUint16(field.name, *field.value, field.envValue)
		if err != nil {
			return ipn.AmneziaWGPrefs{}, err
		}
	}
	for _, field := range []struct {
		name     string
		value    *string
		envValue func() string
	}{
		{"TS_AMNEZIA_I1", &prefs.I1, amneziaI1},
		{"TS_AMNEZIA_I2", &prefs.I2, amneziaI2},
		{"TS_AMNEZIA_I3", &prefs.I3, amneziaI3},
		{"TS_AMNEZIA_I4", &prefs.I4, amneziaI4},
		{"TS_AMNEZIA_I5", &prefs.I5, amneziaI5},
		{"TS_AMNEZIA_HEADER_PROTECTION_KEY", &prefs.HeaderProtectionKey, amneziaHeaderProtectionKey},
	} {
		if *field.value == "" {
			*field.value = field.envValue()
		}
	}
	for _, field := range []struct {
		name     string
		value    *ipn.MagicHeaderRange
		envValue func() int
	}{
		{"TS_AMNEZIA_H1", &prefs.H1, amneziaH1},
		{"TS_AMNEZIA_H2", &prefs.H2, amneziaH2},
		{"TS_AMNEZIA_H3", &prefs.H3, amneziaH3},
		{"TS_AMNEZIA_H4", &prefs.H4, amneziaH4},
	} {
		*field.value, err = resolveHeader(field.name, *field.value, field.envValue)
		if err != nil {
			return ipn.AmneziaWGPrefs{}, err
		}
	}
	for _, field := range []struct {
		name     string
		value    *ipn.MagicHeaderRange
		envValue func() string
	}{
		{"TS_AMNEZIA_CONTENT_PADDING_ADDITION", &prefs.ContentPaddingAddition, amneziaContentPaddingAddition},
		{"TS_AMNEZIA_REKEY_AFTER_TIME", &prefs.RekeyAfterTime, amneziaRekeyAfterTime},
		{"TS_AMNEZIA_REKEY_TIMEOUT", &prefs.RekeyTimeout, amneziaRekeyTimeout},
		{"TS_AMNEZIA_REJECT_AFTER_TIME", &prefs.RejectAfterTime, amneziaRejectAfterTime},
		{"TS_AMNEZIA_KEEPALIVE_TIMEOUT", &prefs.KeepaliveTimeout, amneziaKeepaliveTimeout},
		{"TS_AMNEZIA_MAX_HANDSHAKE_ATTEMPTS", &prefs.MaxHandshakeAttempts, amneziaMaxHandshakeAttempts},
	} {
		*field.value, err = resolveRange(field.name, *field.value, field.envValue)
		if err != nil {
			return ipn.AmneziaWGPrefs{}, err
		}
	}
	if err := ipn.ValidateAmneziaWGConfig(prefs); err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	return prefs, nil
}

func amneziaUAPIConfig(prefs ipn.AmneziaWGPrefs) (string, error) {
	prefs, err := EffectiveAmneziaConfig(prefs)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	set := func(key, value string) {
		fmt.Fprintf(&buf, "%s=%s\n", key, value)
	}
	setUint16 := func(key string, value uint16) {
		set(key, strconv.FormatUint(uint64(value), 10))
	}
	setHeader := func(key string, value ipn.MagicHeaderRange, standard uint32) {
		if value.IsZero() {
			value = ipn.MagicHeaderRange{Min: standard, Max: standard}
		}
		set(key, value.String())
	}

	setUint16("jc", prefs.JC)
	setUint16("jmin", prefs.JMin)
	setUint16("jmax", prefs.JMax)
	setUint16("s1", prefs.S1)
	setUint16("s2", prefs.S2)
	setUint16("s3", prefs.S3)
	setUint16("s4", prefs.S4)
	set("i1", prefs.I1)
	set("i2", prefs.I2)
	set("i3", prefs.I3)
	set("i4", prefs.I4)
	set("i5", prefs.I5)
	setHeader("h1", prefs.H1, device.DefaultMessageInitiationType)
	setHeader("h2", prefs.H2, device.DefaultMessageResponseType)
	setHeader("h3", prefs.H3, device.DefaultMessageCookieReplyType)
	setHeader("h4", prefs.H4, device.DefaultMessageTransportType)

	headerProtectionKey := prefs.HeaderProtectionKey
	if headerProtectionKey == "" {
		headerProtectionKey = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	headerProtectionKeyBytes, err := hex.DecodeString(headerProtectionKey)
	if err != nil || len(headerProtectionKeyBytes) != device.HeaderCipherKeySize {
		return "", fmt.Errorf("header protection key must contain %d hexadecimal characters", device.HeaderCipherKeySize*2)
	}
	if !bytes.Equal(headerProtectionKeyBytes, make([]byte, device.HeaderCipherKeySize)) {
		paddings := []uint16{prefs.S1, prefs.S2, prefs.S3, prefs.S4}
		for i, padding := range paddings {
			if padding < device.HeaderCipherNonceSize {
				return "", fmt.Errorf("S%d must be at least %d when header protection is enabled", i+1, device.HeaderCipherNonceSize)
			}
		}
	}
	set("header_protection_key", headerProtectionKey)
	set("content_padding_addition", prefs.ContentPaddingAddition.String())
	set("rekey_after_time", prefs.RekeyAfterTime.String())
	set("rekey_timeout", prefs.RekeyTimeout.String())
	set("reject_after_time", prefs.RejectAfterTime.String())
	set("keepalive_timeout", prefs.KeepaliveTimeout.String())
	set("max_handshake_attempts", prefs.MaxHandshakeAttempts.String())
	// Emit false as well, so resetting or downgrading a profile cannot leave
	// AWG 3.1 behavior enabled in a long-running device.
	set("random_trailers", strconv.FormatBool(prefs.RandomTrailers))
	set("disable_cookies", strconv.FormatBool(prefs.DisableCookies))

	buf.WriteByte('\n')
	return buf.String(), nil
}
