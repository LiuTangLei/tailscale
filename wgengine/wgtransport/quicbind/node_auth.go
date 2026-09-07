// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	nodeAuthScheme   = "TailnetNode "
	nodeAuthReply    = "X-Tailnet-Node-Auth"
	nodeAuthPinProof = "X-Tailnet-Pinned-Proof"
	nodeAuthLabel    = "EXPORTER-HTTP3-TAILNET-NODE-AUTH-v1"
	nodeProofLen     = 163 // version, direction, src/dst/nonce/exporter/SPKI (32 each), server flag
)

var errNodeProof = errors.New("HTTP/3 Tailnet node authentication failed")

type nodeProof struct {
	from, to, nonce, binding, pin [32]byte
	server                        bool
}

func automaticPeerURL(k [32]byte) *url.URL {
	// The private HTTP authority is encrypted. It is never a public-domain
	// identity, never used for DNS resolution, and omitted from ClientHello SNI.
	// Parse the same URI form as persisted legacy profiles so the literal '*'
	// path representation and TLS request binding stay byte-for-byte aligned.
	u, _ := url.Parse("https://peer-" + hex.EncodeToString(k[:6]) + ".invalid/.well-known/masque/ip/*/*/")
	return u
}
func (b *Backend) localNodeKey() [32]byte {
	if b.factory.cfg.AutoTrust && b.host.NodePublic != nil {
		return b.host.NodePublic()
	}
	return b.factory.local
}
func (b *Backend) automaticPeer(k [32]byte) (peerConfig, error) {
	if k == ([32]byte{}) || k == b.localNodeKey() || !b.peerAllowed(k) {
		return peerConfig{}, ErrUnknownPeer
	}
	if p, ok := b.factory.peers[k]; ok {
		return p, nil
	}
	if !b.factory.cfg.AutoTrust {
		return peerConfig{}, ErrUnknownPeer
	}
	return peerConfig{key: k, http3URL: automaticPeerURL(k)}, nil
}

// TLS establishes an encrypted provisional channel. A valid certificate alone
// does NOT authorize a node. Both directions must pass node-key channel-bound
// proof before the carrier installs the session or releases queued IP packets.
func (b *Backend) tlsConfig(expected *[32]byte) *tls.Config {
	cfg := b.factory.tlsConfig(expected)
	if !b.factory.cfg.AutoTrust {
		return cfg
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != "h3" {
			return errNodeProof
		}
		if expected == nil {
			return nil
		} // CONNECT requires authenticated node proof
		if !b.peerAllowed(*expected) || !b.identityOK.Load() || len(cs.PeerCertificates) == 0 {
			return errNodeProof
		}
		if p, ok := b.factory.peers[*expected]; ok && p.pin != ([32]byte{}) {
			_, err := b.factory.verify(cs, expected)
			return err
		}
		return validCertificate(cs.PeerCertificates[0])
	}
	return cfg
}

func nodeBinding(cs *tls.ConnectionState, r *http.Request, export tlsExporter) (out [32]byte, err error) {
	if cs == nil || cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != "h3" || r.URL == nil || export == nil {
		return out, errNodeProof
	}
	target := sha256.Sum256([]byte(r.Method + "\n" + r.Proto + "\n" + r.Host + "\n" + r.URL.EscapedPath() + "?" + r.URL.RawQuery))
	b, err := export(nodeAuthLabel, target[:], 32)
	if err != nil || len(b) != 32 {
		return out, errNodeProof
	}
	copy(out[:], b)
	clear(b)
	return out, nil
}
func (p nodeProof) marshal(direction byte) []byte {
	b := make([]byte, nodeProofLen)
	b[0] = 1
	b[1] = direction
	copy(b[2:34], p.from[:])
	copy(b[34:66], p.to[:])
	copy(b[66:98], p.nonce[:])
	copy(b[98:130], p.binding[:])
	copy(b[130:162], p.pin[:])
	if p.server {
		b[162] = 1
	}
	return b
}
func parseNodeProof(b []byte, direction byte) (p nodeProof, err error) {
	if len(b) != nodeProofLen || b[0] != 1 || b[1] != direction || b[162] > 1 {
		return p, errNodeProof
	}
	copy(p.from[:], b[2:34])
	copy(p.to[:], b[34:66])
	copy(p.nonce[:], b[66:98])
	copy(p.binding[:], b[98:130])
	copy(p.pin[:], b[130:162])
	p.server = b[162] == 1
	return p, nil
}
func (b *Backend) sealNodeProof(p nodeProof, direction byte) (string, error) {
	if !b.identityOK.Load() || b.localNodeKey() != p.from || !b.peerAllowed(p.to) || b.host.NodeSeal == nil {
		return "", errNodeProof
	}
	raw := p.marshal(direction)
	defer clear(raw)
	sealed, err := b.host.NodeSeal(p.from, p.to, raw)
	if err != nil {
		return "", errNodeProof
	}
	return nodeAuthScheme + hex.EncodeToString(p.from[:]) + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}
func (b *Backend) openNodeProof(value string, direction byte) (nodeProof, error) {
	var zero nodeProof
	if !b.identityOK.Load() || len(value) > 512 || !strings.HasPrefix(value, nodeAuthScheme) || b.host.NodeOpen == nil {
		return zero, errNodeProof
	}
	pub, encoded, ok := strings.Cut(strings.TrimPrefix(value, nodeAuthScheme), ".")
	if !ok {
		return zero, errNodeProof
	}
	remote, err := parseKey(pub)
	if err != nil || !b.peerAllowed(remote) {
		return zero, errNodeProof
	}
	local := b.localNodeKey()
	if local == ([32]byte{}) || local == remote {
		return zero, errNodeProof
	}
	cipher, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(cipher) != nodeProofLen+40 {
		return zero, errNodeProof
	}
	raw, err := b.host.NodeOpen(local, remote, cipher)
	if err != nil {
		return zero, errNodeProof
	}
	defer clear(raw)
	p, err := parseNodeProof(raw, direction)
	if err != nil || p.from != remote || p.to != local || !b.identityOK.Load() || b.localNodeKey() != local || !b.peerAllowed(remote) {
		return zero, errNodeProof
	}
	return p, nil
}
func (b *Backend) createNodeRequest(remote [32]byte, cs *tls.ConnectionState, r *http.Request, export tlsExporter) (string, nodeProof, error) {
	p := nodeProof{from: b.localNodeKey(), to: remote, server: b.factory.cfg.Server, pin: sha256.Sum256(b.factory.cert.Leaf.RawSubjectPublicKeyInfo)}
	if _, err := rand.Read(p.nonce[:]); err != nil {
		return "", p, err
	}
	var err error
	p.binding, err = nodeBinding(cs, r, export)
	if err != nil {
		return "", p, err
	}
	value, err := b.sealNodeProof(p, 1)
	return value, p, err
}

// This only extracts an untrusted claim for a bounded lifecycle lookup. The
// caller must still verifyNodeRequest; no session is authorized here.
func claimedNodeSender(headers http.Header) ([32]byte, error) {
	values := headers.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 512 || !strings.HasPrefix(values[0], nodeAuthScheme) {
		return [32]byte{}, errNodeProof
	}
	pub, _, ok := strings.Cut(strings.TrimPrefix(values[0], nodeAuthScheme), ".")
	if !ok {
		return [32]byte{}, errNodeProof
	}
	return parseKey(pub)
}

func (b *Backend) verifyNodeRequest(cs *tls.ConnectionState, r *http.Request, export tlsExporter) (nodeProof, error) {
	var zero nodeProof
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return zero, errNodeProof
	}
	p, err := b.openNodeProof(values[0], 1)
	if err != nil {
		return zero, err
	}
	expected, err := nodeBinding(cs, r, export)
	if err != nil || subtle.ConstantTimeCompare(p.binding[:], expected[:]) != 1 {
		return zero, errNodeProof
	}
	hint, err := parseServerHint(r.Header)
	if err != nil || hint != boolServerHint(p.server) {
		return zero, errNodeProof
	}
	// Existing explicit manual pins remain additional constraints, including
	// proof that the sender still owns that separately pinned TLS signing key.
	if pinned, ok := b.factory.peers[p.from]; ok && pinned.pin != ([32]byte{}) {
		if p.pin != pinned.pin {
			return zero, errNodeProof
		}
		values := r.Header.Values(nodeAuthPinProof)
		if len(values) != 1 {
			return zero, errNodeProof
		}
		copyRequest := r.Clone(r.Context())
		copyRequest.Header.Set("Authorization", values[0])
		k, err := b.factory.verifyHTTP3Authorization(cs, copyRequest, export)
		if err != nil || k != p.from {
			return zero, errNodeProof
		}
	}
	return p, nil
}
func (b *Backend) createNodeReply(request nodeProof) (string, error) {
	return b.sealNodeProof(nodeProof{from: request.to, to: request.from, nonce: request.nonce, binding: request.binding, pin: sha256.Sum256(b.factory.cert.Leaf.RawSubjectPublicKeyInfo), server: b.factory.cfg.Server}, 2)
}
func (b *Backend) verifyNodeReply(request nodeProof, cs *tls.ConnectionState, headers http.Header) (uint32, error) {
	values := headers.Values(nodeAuthReply)
	if len(values) != 1 {
		return serverUnknown, errNodeProof
	}
	p, err := b.openNodeProof(values[0], 2)
	if err != nil {
		return serverUnknown, err
	}
	if p.from != request.to || p.to != request.from || !bytes.Equal(p.nonce[:], request.nonce[:]) || subtle.ConstantTimeCompare(p.binding[:], request.binding[:]) != 1 || cs == nil || len(cs.PeerCertificates) == 0 {
		return serverUnknown, errNodeProof
	}
	if p.pin != sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo) {
		return serverUnknown, errNodeProof
	}
	hint, err := parseServerHint(headers)
	if err != nil || hint != boolServerHint(p.server) {
		return serverUnknown, errNodeProof
	}
	return hint, nil
}
func boolServerHint(v bool) uint32 {
	if v {
		return serverYes
	}
	return serverNo
}

func (b *Backend) autoTrustReady() error {
	if b.factory.cfg.AutoTrust && (b.host.NodePublic == nil || b.host.NodeSeal == nil || b.host.NodeOpen == nil) {
		return fmt.Errorf("automatic H3 trust requires host node-key authentication callbacks")
	}
	return nil
}
