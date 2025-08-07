// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgcfg

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"tailscale.com/envknob"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var (
	// Amnezia-WG environment knobs
	// JC, JMin, JMax, S1, S2 default to 0 for standard WireGuard compatibility
	// H1-H4 default to 1,2,3,4 respectively for standard WireGuard magic headers
	amneziaJC   = envknob.RegisterInt("TS_AMNEZIA_JC")
	amneziaJMin = envknob.RegisterInt("TS_AMNEZIA_JMIN")
	amneziaJMax = envknob.RegisterInt("TS_AMNEZIA_JMAX")
	amneziaS1   = envknob.RegisterInt("TS_AMNEZIA_S1")
	amneziaS2   = envknob.RegisterInt("TS_AMNEZIA_S2")
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

		h1 := cfg.AmneziaH1
		if h1 == 0 {
			if envH1 := uint32(amneziaH1()); envH1 > 0 {
				h1 = envH1
			} else {
				h1 = 1 // Default for standard WireGuard compatibility
			}
		}
		set("h1", strconv.FormatUint(uint64(h1), 10))

		h2 := cfg.AmneziaH2
		if h2 == 0 {
			if envH2 := uint32(amneziaH2()); envH2 > 0 {
				h2 = envH2
			} else {
				h2 = 2 // Default for standard WireGuard compatibility
			}
		}
		set("h2", strconv.FormatUint(uint64(h2), 10))

		h3 := cfg.AmneziaH3
		if h3 == 0 {
			if envH3 := uint32(amneziaH3()); envH3 > 0 {
				h3 = envH3
			} else {
				h3 = 3 // Default for standard WireGuard compatibility
			}
		}
		set("h3", strconv.FormatUint(uint64(h3), 10))

		h4 := cfg.AmneziaH4
		if h4 == 0 {
			if envH4 := uint32(amneziaH4()); envH4 > 0 {
				h4 = envH4
			} else {
				h4 = 4 // Default for standard WireGuard compatibility
			}
		}
		set("h4", strconv.FormatUint(uint64(h4), 10))
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
