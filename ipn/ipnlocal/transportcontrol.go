// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/transportprofile"
	"tailscale.com/wgengine/wgcfg"
)

// TransportStatus returns only public identity material and running-vs-pending
// metadata. It never creates identity files as a side effect of inspection.
func (b *LocalBackend) TransportStatus() (ipn.TransportControlStatus, error) {
	b.transportProfileMu.Lock()
	defer b.transportProfileMu.Unlock()
	return b.transportStatusLocked()
}
func (b *LocalBackend) transportStatusLocked() (ipn.TransportControlStatus, error) {
	running := b.StatusWithoutPeers()
	s := ipn.TransportControlStatus{ActiveMode: running.PacketTransport, DesiredMode: running.PacketTransport, Source: running.PacketTransportSource, Revision: "0", Peers: []ipn.TransportPeer{}}
	if s.ActiveMode == "" {
		s.ActiveMode = "unknown"
		s.DesiredMode = "unknown"
	}
	if self := b.currentNode().Self(); self.Valid() {
		s.LocalPublicKey = self.Key().String()
	}
	prefs := b.Prefs()
	var awg ipn.AmneziaWGPrefs
	if prefs.Valid() {
		awg = prefs.AmneziaWG()
	}
	effectiveAWG, awgErr := wgcfg.EffectiveAmneziaConfig(awg)
	s.AWGConfigured = awgErr != nil || !effectiveAWG.IsZero()
	if awgErr != nil {
		s.Warnings = append(s.Warnings, "AWG environment/configuration is invalid; fix it before switching transports.")
	}
	root := b.TailscaleVarRoot()
	s.Available = running.PacketTransportManaged && filepath.IsAbs(root)
	if !s.Available {
		s.Warnings = append(s.Warnings, "This host does not reload managed transport profiles; configure its embedding application instead.")
		return s, nil
	}
	p, rev, err := transportprofile.Read(root)
	if err != nil {
		return s, err
	}
	s.Revision = rev
	public := p.Public(rev)
	s.Identity = public.Identity
	if p.AutoTrust && s.Identity != nil && s.LocalPublicKey != "" {
		current := strings.TrimPrefix(s.LocalPublicKey, "nodekey:")
		old := s.Identity.PublicKey
		if len(current) == 64 && len(old) == 64 {
			if s.Identity.HTTP3URL == "https://peer-"+old[:12]+".invalid/.well-known/masque/ip/*/*/" {
				s.Identity.HTTP3URL = "https://peer-" + current[:12] + ".invalid/.well-known/masque/ip/*/*/"
			}
			s.Identity.PublicKey = current
		}
	}
	s.Peers = public.Peers
	s.Server = p.Server
	s.AutoTrust = p.AutoTrust
	s.Authentication = public.Authentication
	s.MixedPeerSupport = false
	if p.AutoTrust {
		s.UnconfiguredPeers = nil
	} else {
		s.UnconfiguredPeers = b.transportPeerCoverage(p)
	}
	if s.Source == "environment" || s.Source == "embedded" {
		s.DesiredMode = s.ActiveMode
		s.Warnings = append(s.Warnings, "The running transport is explicitly configured outside this CLI. Remove that override before staging a mode; no service configuration is edited automatically.")
	} else {
		s.DesiredMode = p.Mode
		s.PendingRestart = s.ActiveMode != p.Mode || (p.Mode != "native" && rev != running.PacketTransportRevision)
	}
	if s.Identity == nil {
		if p.Mode == "quic-ip" {
			s.Warnings = append(s.Warnings, "The legacy raw QUIC profile requires explicit public identity pins.")
		} else {
			s.Warnings = append(s.Warnings, "Selecting HTTP/3 prepares a local TLS identity automatically; no peer-card export/import or AWG synchronization is required.")
		}
	}
	if p.Identity != nil && p.LocalKey != "" && "nodekey:"+p.LocalKey != s.LocalPublicKey && !p.AutoTrust {
		s.Warnings = append(s.Warnings, "Stored transport identity belongs to a different node/profile; QUIC activation is blocked.")
	}
	if p.Mode != "native" || (s.ActiveMode != "native" && s.ActiveMode != "unknown") {
		if p.AutoTrust {
			s.Warnings = append(s.Warnings, "HTTP/3 auto-trust authenticates by the current authorized Tailnet node key; explicit manual pins remain additional constraints.")
		} else {
			s.Warnings = append(s.Warnings, "QUIC is a node-wide data plane in this build; native communication with old peers does not run concurrently. A trusted identity card is not evidence that the peer enabled the same protocol.")
			if len(s.UnconfiguredPeers) != 0 {
				s.Warnings = append(s.Warnings, fmt.Sprintf("%d routable peers are missing QUIC identity configuration. Control-plane online status does not prove their data-plane reachability.", len(s.UnconfiguredPeers)))
			}
		}
	}
	if p.Mode == "http3-ip" {
		if p.AutoTrust {
			s.Warnings = append(s.Warnings, "HTTP/3 is experimental, not a Chrome fingerprint clone. The generated .invalid authority is private and authenticated by the current authorized Tailnet node key, not a public domain certificate.")
		} else {
			s.Warnings = append(s.Warnings, "HTTP/3 is experimental, not a Chrome fingerprint clone. The generated .invalid authority is private and authenticated by a pinned key, not a public domain certificate.")
		}
	}
	return s, nil
}

// ConfigureTransport only stages a next-start profile. Restart is deliberately
// external: automatically restarting over this connection could lock out the
// administrator. The normal AWG preferences and production socket stay intact.
func (b *LocalBackend) ConfigureTransport(ctx context.Context, req ipn.TransportControlRequest) (ipn.TransportControlStatus, error) {
	b.transportProfileMu.Lock()
	defer b.transportProfileMu.Unlock()
	s, err := b.transportStatusLocked()
	if err != nil {
		return s, err
	}
	if !s.Available {
		return s, errors.New("managed transport is unavailable on this host")
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	if req.Action != "validate" && (req.ExpectedRevision == "" || req.ExpectedRevision != s.Revision) {
		return s, transportprofile.ErrConflict
	}
	if req.Action != "validate" && (s.Source == "environment" || s.Source == "embedded") {
		return s, errors.New("transport is externally configured; no managed changes were saved")
	}
	if req.Action == "mode" && req.Mode != "native" && s.AWGConfigured {
		return s, errors.New("QUIC-IP does not use AWG; explicitly reset AWG preferences before selecting it (this can interrupt native AWG peers)")
	}
	if req.Action == "add-peer" && req.Peer != nil {
		var pk key.NodePublic
		value := req.Peer.PublicKey
		if len(value) == 64 {
			value = "nodekey:" + value
		}
		if err := pk.UnmarshalText([]byte(value)); err != nil {
			return s, errors.New("invalid peer node public key")
		}
		if _, ok := b.currentNode().PeerAllowedIPs(pk); !ok {
			return s, errors.New("identity card must belong to a currently authorized and routable tailnet peer")
		}
	}
	p, _, err := transportprofile.Read(b.TailscaleVarRoot())
	if err != nil {
		return s, err
	}
	p, err = transportprofile.Apply(p, req, s.LocalPublicKey)
	if err != nil {
		return s, err
	}
	if err := b.checkTransportPeerCoverage(p); err != nil {
		return s, err
	}
	if req.Action == "validate" {
		return s, nil
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	if _, err := transportprofile.Save(b.TailscaleVarRoot(), p, s.Revision); err != nil {
		return s, fmt.Errorf("stage transport: %w", err)
	}
	return b.transportStatusLocked()
}
