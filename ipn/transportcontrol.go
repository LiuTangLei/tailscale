// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

// TransportPeer is a public identity card, not an authentication secret.
// Import only over an already trusted channel; never trust arbitrary network
// discovery or a matching display name. No private key is returned by LocalAPI.
type TransportPeer struct {
	Name       string `json:"name,omitempty"`
	PublicKey  string `json:"public_key"`
	SPKISHA256 string `json:"spki_sha256"`
	HTTP3URL   string `json:"http3_url,omitempty"`
	// Server is a public declaration, not a per-peer role or permission.
	Server bool `json:"server,omitempty"`
}

// TransportUnconfiguredPeer identifies a routable Tailnet peer for which the
// managed QUIC profile has no authenticated transport identity. It is not a
// claim about the peer's software version or protocol support.
type TransportUnconfiguredPeer struct {
	PublicKey string `json:"public_key"`
	Name      string `json:"name,omitempty"`
}

// TransportControlStatus separates the running engine from the next-start
// profile. A successful mutation never implies a running mode switch.
type TransportControlStatus struct {
	ActiveMode     string `json:"active_mode"`
	DesiredMode    string `json:"desired_mode"`
	PendingRestart bool   `json:"pending_restart"`
	Available      bool   `json:"available"`
	Source         string `json:"source"`
	Revision       string `json:"revision"`
	// Server is the configured next-start declaration. PendingRestart must
	// be checked before treating it as the running HTTP/3 setting.
	Server            bool                        `json:"server"`
	AutoTrust         bool                        `json:"auto_trust,omitempty"`
	Authentication    string                      `json:"authentication,omitempty"`
	LocalPublicKey    string                      `json:"local_public_key,omitempty"`
	Identity          *TransportPeer              `json:"identity,omitempty"`
	Peers             []TransportPeer             `json:"peers"`
	AWGConfigured     bool                        `json:"awg_configured"`
	Warnings          []string                    `json:"warnings,omitempty"`
	MixedPeerSupport  bool                        `json:"mixed_peer_support"`
	UnconfiguredPeers []TransportUnconfiguredPeer `json:"unconfigured_peers,omitempty"`
}

// TransportControlRequest is an explicit local mutation. ExpectedRevision is
// required for every action and prevents stale interactive prompts overwriting
// a concurrent administrator's changes. Actions: prepare, add-peer, remove-peer,
// mode, server, validate. validate is read-only and needs no revision.
type TransportControlRequest struct {
	Action           string `json:"action"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	Mode             string `json:"mode,omitempty"`
	// Pointer distinguishes an explicit false from a missing update.
	Server    *bool          `json:"server,omitempty"`
	AutoTrust *bool          `json:"auto_trust,omitempty"`
	Peer      *TransportPeer `json:"peer,omitempty"`
	PublicKey string         `json:"public_key,omitempty"`
}
