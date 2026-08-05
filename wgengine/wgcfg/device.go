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
	return device.NewDevice(tunDev, bind, logger)
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

func amneziaUAPIConfig(prefs ipn.AmneziaWGPrefs) (string, error) {
	var buf bytes.Buffer
	var configErr error
	set := func(key, value string) {
		fmt.Fprintf(&buf, "%s=%s\n", key, value)
	}
	resolveUint16 := func(value uint16, envValue func() int) uint16 {
		if value == 0 {
			return uint16(envValue())
		}
		return value
	}
	setUint16 := func(key string, value uint16, envValue func() int) {
		value = resolveUint16(value, envValue)
		set(key, strconv.FormatUint(uint64(value), 10))
	}
	setString := func(key, value string, envValue func() string) {
		if value == "" {
			value = envValue()
		}
		set(key, value)
	}
	setRange := func(key string, value ipn.MagicHeaderRange, envValue func() string) {
		if value.IsZero() {
			env := envValue()
			if env == "" {
				set(key, "0")
				return
			}
			var err error
			value, err = ipn.ParseMagicHeaderRange(env)
			if err != nil {
				configErr = fmt.Errorf("invalid %s environment value %q: %w", key, env, err)
				return
			}
		}
		set(key, value.String())
	}
	setHeader := func(key string, value ipn.MagicHeaderRange, envValue func() int, standard uint32) {
		if value.IsZero() {
			if configured := uint32(envValue()); configured != 0 {
				value = ipn.MagicHeaderRange{Min: configured, Max: configured}
			} else {
				value = ipn.MagicHeaderRange{Min: standard, Max: standard}
			}
		}
		set(key, value.String())
	}

	setUint16("jc", prefs.JC, amneziaJC)
	setUint16("jmin", prefs.JMin, amneziaJMin)
	setUint16("jmax", prefs.JMax, amneziaJMax)
	setUint16("s1", prefs.S1, amneziaS1)
	setUint16("s2", prefs.S2, amneziaS2)
	setUint16("s3", prefs.S3, amneziaS3)
	setUint16("s4", prefs.S4, amneziaS4)
	setString("i1", prefs.I1, amneziaI1)
	setString("i2", prefs.I2, amneziaI2)
	setString("i3", prefs.I3, amneziaI3)
	setString("i4", prefs.I4, amneziaI4)
	setString("i5", prefs.I5, amneziaI5)
	setHeader("h1", prefs.H1, amneziaH1, device.DefaultMessageInitiationType)
	setHeader("h2", prefs.H2, amneziaH2, device.DefaultMessageResponseType)
	setHeader("h3", prefs.H3, amneziaH3, device.DefaultMessageCookieReplyType)
	setHeader("h4", prefs.H4, amneziaH4, device.DefaultMessageTransportType)

	headerProtectionKey := prefs.HeaderProtectionKey
	if headerProtectionKey == "" {
		headerProtectionKey = amneziaHeaderProtectionKey()
	}
	if headerProtectionKey == "" {
		headerProtectionKey = "0000000000000000000000000000000000000000000000000000000000000000"
	}
	headerProtectionKeyBytes, err := hex.DecodeString(headerProtectionKey)
	if err != nil || len(headerProtectionKeyBytes) != device.HeaderCipherKeySize {
		return "", fmt.Errorf("header protection key must contain %d hexadecimal characters", device.HeaderCipherKeySize*2)
	}
	if !bytes.Equal(headerProtectionKeyBytes, make([]byte, device.HeaderCipherKeySize)) {
		paddings := []uint16{
			resolveUint16(prefs.S1, amneziaS1),
			resolveUint16(prefs.S2, amneziaS2),
			resolveUint16(prefs.S3, amneziaS3),
			resolveUint16(prefs.S4, amneziaS4),
		}
		for i, padding := range paddings {
			if padding < device.HeaderCipherNonceSize {
				return "", fmt.Errorf("S%d must be at least %d when header protection is enabled", i+1, device.HeaderCipherNonceSize)
			}
		}
	}
	set("header_protection_key", headerProtectionKey)
	setRange("content_padding_addition", prefs.ContentPaddingAddition, amneziaContentPaddingAddition)
	setRange("rekey_after_time", prefs.RekeyAfterTime, amneziaRekeyAfterTime)
	setRange("rekey_timeout", prefs.RekeyTimeout, amneziaRekeyTimeout)
	setRange("reject_after_time", prefs.RejectAfterTime, amneziaRejectAfterTime)
	setRange("keepalive_timeout", prefs.KeepaliveTimeout, amneziaKeepaliveTimeout)
	setRange("max_handshake_attempts", prefs.MaxHandshakeAttempts, amneziaMaxHandshakeAttempts)
	if configErr != nil {
		return "", configErr
	}

	buf.WriteByte('\n')
	return buf.String(), nil
}
