// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var (
	// Amnezia-WG 1.5 environment knobs
	// JC, JMin, JMax, S1, S2, S3, S4 default to 0 for standard WireGuard compatibility
	// I1-I5 are Custom Protocol Signature (CPS) packets for protocol masking
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

// ToUAPI writes cfg in UAPI format to w.
// Prev is the previous device Config.
//
// Prev is required so that we can remove now-defunct peers without having to
// remove and re-add all peers, and so that we can avoid writing information
// about peers that have not changed since the previous time we wrote our
// Config.
func (cfg *Config) ToUAPI(logf logger.Logf, w io.Writer, prev *Config) error {
	var stickyErr error
	set := func(key, value string) {
		if stickyErr != nil {
			return
		}
		_, err := fmt.Fprintf(w, "%s=%s\n", key, value)
		if err != nil {
			stickyErr = err
		}
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
	setPeer := func(peer Peer) {
		set("public_key", peer.PublicKey.UntypedHexString())
	}

	// Device config.
	if !prev.PrivateKey.Equal(cfg.PrivateKey) {
		set("private_key", cfg.PrivateKey.UntypedHexString())

		// Apply Amnezia-WG parameters from config or environment
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

		// Custom Protocol Signature (CPS) packets for AmneziaWG 1.5
		// If I1 is missing, the entire signature chain (I2-I5) is skipped for 1.0 compatibility
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

		// Header field parameters (H1-H4)
		h1 := cfg.AmneziaH1
		if h1.Min == 0 && h1.Max == 0 {
			h1Val := uint32(amneziaH1())
			if h1Val > 0 {
				h1 = ipn.MagicHeaderRange{Min: h1Val, Max: h1Val}
			}
		}
		if h1.Min > 0 || h1.Max > 0 {
			setMagicHeaderRange("h1", h1)
		}

		h2 := cfg.AmneziaH2
		if h2.Min == 0 && h2.Max == 0 {
			h2Val := uint32(amneziaH2())
			if h2Val > 0 {
				h2 = ipn.MagicHeaderRange{Min: h2Val, Max: h2Val}
			}
		}
		if h2.Min > 0 || h2.Max > 0 {
			setMagicHeaderRange("h2", h2)
		}

		h3 := cfg.AmneziaH3
		if h3.Min == 0 && h3.Max == 0 {
			h3Val := uint32(amneziaH3())
			if h3Val > 0 {
				h3 = ipn.MagicHeaderRange{Min: h3Val, Max: h3Val}
			}
		}
		if h3.Min > 0 || h3.Max > 0 {
			setMagicHeaderRange("h3", h3)
		}

		h4 := cfg.AmneziaH4
		if h4.Min == 0 && h4.Max == 0 {
			h4Val := uint32(amneziaH4())
			if h4Val > 0 {
				h4 = ipn.MagicHeaderRange{Min: h4Val, Max: h4Val}
			}
		}
		if h4.Min > 0 || h4.Max > 0 {
			setMagicHeaderRange("h4", h4)
		}
	}

	old := make(map[key.NodePublic]Peer)
	for _, p := range prev.Peers {
		old[p.PublicKey] = p
	}

	// Add/configure all new peers.
	for _, p := range cfg.Peers {
		oldPeer, wasPresent := old[p.PublicKey]

		// We only want to write the peer header/version if we're about
		// to change something about that peer, or if it's a new peer.
		// Figure out up-front whether we'll need to do anything for
		// this peer, and skip doing anything if not.
		//
		// If the peer was not present in the previous config, this
		// implies that this is a new peer; set all of these to 'true'
		// to ensure that we're writing the full peer configuration.
		willSetEndpoint := oldPeer.WGEndpoint != p.PublicKey || !wasPresent
		willChangeIPs := !cidrsEqual(oldPeer.AllowedIPs, p.AllowedIPs) || !wasPresent
		willChangeKeepalive := oldPeer.PersistentKeepalive != p.PersistentKeepalive // if not wasPresent, no need to redundantly set zero (default)

		if !willSetEndpoint && !willChangeIPs && !willChangeKeepalive {
			// It's safe to skip doing anything here; wireguard-go
			// will not remove a peer if it's unspecified unless we
			// tell it to (which we do below if necessary).
			continue
		}

		setPeer(p)
		set("protocol_version", "1")

		// Avoid setting endpoints if the correct one is already known
		// to WireGuard, because doing so generates a bit more work in
		// calling magicsock's ParseEndpoint for effectively a no-op.
		if willSetEndpoint {
			if wasPresent {
				// We had an endpoint, and it was wrong.
				// By construction, this should not happen.
				// If it does, keep going so that we can recover from it,
				// but log so that we know about it,
				// because it is an indicator of other failed invariants.
				// See corp issue 3016.
				logf("[unexpected] endpoint changed from %s to %s", oldPeer.WGEndpoint, p.PublicKey)
			}
			set("endpoint", p.PublicKey.UntypedHexString())
		}

		// TODO: replace_allowed_ips is expensive.
		// If p.AllowedIPs is a strict superset of oldPeer.AllowedIPs,
		// then skip replace_allowed_ips and instead add only
		// the new ipps with allowed_ip.
		if willChangeIPs {
			set("replace_allowed_ips", "true")
			for _, ipp := range p.AllowedIPs {
				set("allowed_ip", ipp.String())
			}
		}

		// Set PersistentKeepalive after the peer is otherwise configured,
		// because it can trigger handshake packets.
		if willChangeKeepalive {
			setUint16("persistent_keepalive_interval", p.PersistentKeepalive)
		}
	}

	// Remove peers that were present but should no longer be.
	for _, p := range cfg.Peers {
		delete(old, p.PublicKey)
	}
	for _, p := range old {
		setPeer(p)
		set("remove", "true")
	}

	if stickyErr != nil {
		stickyErr = fmt.Errorf("ToUAPI: %w", stickyErr)
	}
	return stickyErr
}

func cidrsEqual(x, y []netip.Prefix) bool {
	// TODO: re-implement using netaddr.IPSet.Equal.
	if len(x) != len(y) {
		return false
	}
	// First see if they're equal in order, without allocating.
	exact := true
	for i := range x {
		if x[i] != y[i] {
			exact = false
			break
		}
	}
	if exact {
		return true
	}

	// Otherwise, see if they're the same, but out of order.
	m := make(map[netip.Prefix]bool)
	for _, v := range x {
		m[v] = true
	}
	for _, v := range y {
		if !m[v] {
			return false
		}
	}
	return true
}
