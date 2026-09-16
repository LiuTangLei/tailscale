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
			s.Warnings = append(s.Warnings, "Selecting QUIC prepares its identity automatically and clears saved AWG settings; no peer-card export/import or AWG synchronization is required.")
		}
	}
	if p.Identity != nil && p.LocalKey != "" && "nodekey:"+p.LocalKey != s.LocalPublicKey && !p.AutoTrust {
		s.Warnings = append(s.Warnings, "Stored transport identity belongs to a different node/profile; QUIC activation is blocked.")
	}
	if p.Mode != "native" || (s.ActiveMode != "native" && s.ActiveMode != "unknown") {
		if p.AutoTrust {
			s.Warnings = append(s.Warnings, "QUIC auto-trust authenticates by the current authorized Tailnet node key; explicit manual pins remain additional constraints.")
		} else {
			s.Warnings = append(s.Warnings, "QUIC is a node-wide data plane in this build; native communication with old peers does not run concurrently. A trusted identity card is not evidence that the peer enabled the same protocol.")
			if len(s.UnconfiguredPeers) != 0 {
				s.Warnings = append(s.Warnings, fmt.Sprintf("%d routable peers are missing QUIC identity configuration. Control-plane online status does not prove their data-plane reachability.", len(s.UnconfiguredPeers)))
			}
		}
	}
	if p.Mode == "http3-ip" {
		if p.AutoTrust {
			s.Warnings = append(s.Warnings, "QUIC obfuscation is not a Chrome fingerprint clone. Its private authority is authenticated by the current authorized Tailnet node key, not a public domain certificate.")
		} else {
			s.Warnings = append(s.Warnings, "QUIC obfuscation is not a Chrome fingerprint clone. Its private authority is authenticated by a pinned key, not a public domain certificate.")
		}
	}
	return s, nil
}

// ConfigureTransport only stages a next-start profile. Restart is deliberately
// external: automatically restarting over this connection could lock out the
// administrator. Selecting QUIC also clears the separately persisted AWG
// profile, after transport validation and saving have succeeded. Selecting AWG
// stages native mode and saves its profile without changing the running QUIC engine.
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
	if req.Action == "mode" && req.Mode == "quic" {
		req.Mode = "http3-ip"
		autoTrust := true
		req.AutoTrust = &autoTrust
	}
	var awgUpdate *ipn.AmneziaWGPrefs
	if req.Action == "awg" {
		if req.AWG == nil {
			return s, errors.New("AWG configuration is required; no settings were changed")
		}
		if _, err := wgcfg.EffectiveAmneziaConfig(*req.AWG); err != nil {
			return s, fmt.Errorf("invalid AWG configuration: %w", err)
		}
		config := *req.AWG
		awgUpdate = &config
		req.Action, req.Mode = "mode", "native"
	}
	resetAWG := req.Action == "mode" && (req.Mode == "http3-ip" || req.Mode == "quic-ip")
	if resetAWG {
		awgUpdate = new(ipn.AmneziaWGPrefs)
		// Stored preferences can be cleared here, but process environment
		// overrides cannot. Reject those before changing either state file.
		effective, err := wgcfg.EffectiveAmneziaConfig(ipn.AmneziaWGPrefs{})
		if err != nil || !effective.IsZero() {
			return s, errors.New("remove TS_AMNEZIA_* environment overrides before selecting QUIC; no settings were changed")
		}
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
	previous := p
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
	if err := b.saveTransportSelection(p, previous, s, awgUpdate); err != nil {
		return s, err
	}
	return b.transportStatusLocked()
}

// saveTransportSelection serializes the AWG update with transport changes.
// Persist before updating in-memory preferences: the ordinary EditPrefs path
// only logs store errors. A running QUIC engine does not consume saved AWG
// parameters; they become active when the staged native engine starts.
func (b *LocalBackend) saveTransportSelection(next, previous transportprofile.Profile, status ipn.TransportControlStatus, awgUpdate *ipn.AmneziaWGPrefs) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if awgUpdate != nil {
		self := b.currentNode().Self()
		if !self.Valid() || self.Key().String() != status.LocalPublicKey {
			return transportprofile.ErrConflict
		}
	}
	prefs := b.pm.CurrentPrefs()
	var update func() error
	if awgUpdate != nil && prefs.Valid() && prefs.AmneziaWG() != *awgUpdate {
		updated := prefs.AsStruct()
		updated.AmneziaWG = *awgUpdate
		// Only the AWG field changes, and it was validated for the next
		// engine above. Do not validate it against the still-running QUIC
		// engine or apply it to that engine before the deliberate restart.
		stateKey := b.pm.CurrentProfile().Key()
		if stateKey == "" {
			return errors.New("log in before switching transport; no settings were changed")
		}
		update = func() error {
			if err := b.pm.writePrefsToStore(stateKey, updated.View()); err != nil {
				return err
			}
			b.setPrefsLocked(updated)
			return nil
		}
	}
	return saveTransportWithAWGUpdate(b.TailscaleVarRoot(), previous, next, status.Revision, update)
}

// Do not change AWG if transport saving fails. If the AWG store rejects the
// write, restore the previous transport selection and report either failure.
func saveTransportWithAWGUpdate(root string, previous, next transportprofile.Profile, revision string, update func() error) error {
	savedRevision, err := transportprofile.Save(root, next, revision)
	if err != nil {
		return fmt.Errorf("stage transport: %w", err)
	}
	if update != nil {
		if err := update(); err != nil {
			_, rollbackErr := transportprofile.Save(root, previous, savedRevision)
			if rollbackErr != nil {
				return errors.Join(fmt.Errorf("save AWG: %w", err), fmt.Errorf("restore transport: %w", rollbackErr))
			}
			return fmt.Errorf("save AWG (transport selection restored): %w", err)
		}
	}
	return nil
}
