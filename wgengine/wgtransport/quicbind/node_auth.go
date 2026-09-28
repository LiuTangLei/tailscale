// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"tailscale.com/wgengine/wgtransport/nodeauth"
)

const (
	nodeAuthScheme = "TailnetNoiseIKv2 "
	nodeAuthReply  = "X-Tailnet-Node-Auth"
	nodeAuthLabel  = "EXPORTER-HTTP3-TAILNET-NODE-AUTH-v2"
	nodeProofLen   = 163 // version, direction, src/dst/nonce/exporter/SPKI (32 each), server flag
)

var errNodeProof = errors.New("HTTP/3 Tailnet node authentication failed")

type nodeProof struct {
	from, to, nonce, binding, pin [32]byte
	server                        bool
	pinnedProof                   string
	handshake                     nodeauth.Handshake
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

// authenticatedNodeBinding binds an optional application credential to this
// exact TLS connection and CONNECT target, before either Noise message can be
// accepted. A bootstrap proof cannot be relayed into a different TLS session.
func (b *Backend) authenticatedNodeBinding(cs *tls.ConnectionState, r *http.Request, export tlsExporter) ([32]byte, error) {
	binding, err := nodeBinding(cs, r, export)
	if err != nil || b.factory.cfg.AuthenticationSecret == ([32]byte{}) {
		return binding, err
	}
	mac := hmac.New(sha256.New, b.factory.cfg.AuthenticationSecret[:])
	mac.Write([]byte("tailcat-h3/application-node-binding/v1\x00"))
	mac.Write(binding[:])
	copy(binding[:], mac.Sum(nil))
	return binding, nil
}

func (p nodeProof) marshal(direction byte) []byte {
	b := make([]byte, nodeProofLen)
	b[0] = 2
	b[1] = direction
	copy(b[2:34], p.from[:])
	copy(b[34:66], p.to[:])
	copy(b[66:98], p.nonce[:])
	copy(b[98:130], p.binding[:])
	copy(b[130:162], p.pin[:])
	if p.server {
		b[162] = 1
	}
	return append(b, []byte(p.pinnedProof)...)
}
func parseNodeProof(b []byte, direction byte) (p nodeProof, err error) {
	if len(b) < nodeProofLen || len(b) > 2048 || b[0] != 2 || b[1] != direction || b[162] > 1 {
		return p, errNodeProof
	}
	copy(p.from[:], b[2:34])
	copy(p.to[:], b[34:66])
	copy(p.nonce[:], b[66:98])
	copy(p.binding[:], b[98:130])
	copy(p.pin[:], b[130:162])
	p.server = b[162] == 1
	p.pinnedProof = string(b[163:])
	return p, nil
}
func encodeNodeMessage(raw []byte) string {
	return nodeAuthScheme + base64.RawURLEncoding.EncodeToString(raw)
}
func decodeNodeMessage(value string) ([]byte, error) {
	if len(value) > 5500 || !strings.HasPrefix(value, nodeAuthScheme) {
		return nil, errNodeProof
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, nodeAuthScheme))
	if err != nil || len(raw) > 4096 {
		return nil, errNodeProof
	}
	return raw, nil
}
func (b *Backend) createNodeRequest(remote [32]byte, cs *tls.ConnectionState, r *http.Request, export tlsExporter) (string, nodeProof, error) {
	p := nodeProof{from: b.localNodeKey(), to: remote, server: b.factory.cfg.Server, pin: sha256.Sum256(b.factory.cert.Leaf.RawSubjectPublicKeyInfo)}
	if _, err := rand.Read(p.nonce[:]); err != nil {
		return "", p, err
	}
	var err error
	p.binding, err = b.authenticatedNodeBinding(cs, r, export)
	if err != nil {
		return "", p, err
	}
	p.pinnedProof, err = b.factory.http3Authorization(cs, r, export)
	if err != nil {
		return "", p, err
	}
	p.handshake, err = b.host.NodeHandshake(p.from, remote, true, p.binding[:])
	if err != nil {
		return "", p, err
	}
	raw, err := p.handshake.Write(p.marshal(1))
	if err != nil {
		p.handshake.Close()
		return "", p, err
	}
	return encodeNodeMessage(raw), p, nil
}

func (b *Backend) verifyNodeRequest(cs *tls.ConnectionState, r *http.Request, export tlsExporter) (nodeProof, error) {
	var zero nodeProof
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return zero, errNodeProof
	}
	binding, err := b.authenticatedNodeBinding(cs, r, export)
	if err != nil {
		return zero, err
	}
	local := b.localNodeKey()
	hs, err := b.host.NodeHandshake(local, [32]byte{}, false, binding[:])
	if err != nil {
		return zero, err
	}
	keep := false
	defer func() {
		if !keep {
			hs.Close()
		}
	}()
	raw, err := decodeNodeMessage(values[0])
	if err != nil {
		return zero, err
	}
	plain, err := hs.Read(raw)
	if err != nil {
		return zero, err
	}
	defer clear(plain)
	p, err := parseNodeProof(plain, 1)
	if err != nil || p.from != hs.Peer() || p.to != local || p.binding != binding || !b.identityOK.Load() || b.localNodeKey() != local || !b.peerAllowed(p.from) {
		return zero, errNodeProof
	}
	p.handshake = hs
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
		if p.pinnedProof == "" {
			return zero, errNodeProof
		}
		copyRequest := r.Clone(r.Context())
		copyRequest.Header.Set("Authorization", p.pinnedProof)
		k, err := b.factory.verifyHTTP3Authorization(cs, copyRequest, export)
		if err != nil || k != p.from {
			return zero, errNodeProof
		}
	}
	keep = true
	return p, nil
}
func (b *Backend) createNodeReply(request nodeProof) (string, error) {
	p := nodeProof{from: request.to, to: request.from, nonce: request.nonce, binding: request.binding, pin: sha256.Sum256(b.factory.cert.Leaf.RawSubjectPublicKeyInfo), server: b.factory.cfg.Server}
	raw, err := request.handshake.Write(p.marshal(2))
	if err != nil {
		return "", err
	}
	return encodeNodeMessage(raw), nil
}
func (b *Backend) verifyNodeReply(request nodeProof, cs *tls.ConnectionState, headers http.Header) (uint32, error) {
	if !b.identityOK.Load() || b.localNodeKey() != request.from || !b.peerAllowed(request.to) {
		return serverUnknown, errNodeProof
	}
	values := headers.Values(nodeAuthReply)
	if len(values) != 1 {
		return serverUnknown, errNodeProof
	}
	raw, err := decodeNodeMessage(values[0])
	if err != nil {
		return serverUnknown, err
	}
	plain, err := request.handshake.Read(raw)
	if err != nil {
		return serverUnknown, err
	}
	defer clear(plain)
	p, err := parseNodeProof(plain, 2)
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
	if b.factory.cfg.AutoTrust && (b.host.NodePublic == nil || b.host.NodeHandshake == nil) {
		return fmt.Errorf("automatic H3 trust requires host node-key authentication callbacks")
	}
	return nil
}

// These bounded private capsules are exchanged before starting the generic
// capsule reader. A 200 response is provisional until both Finished messages
// verify. The encrypted role strings prevent reflection and require IK split keys.
const nodeFinishedCapsule byte = 0x3e

func writeNodeFinished(w io.Writer, hs nodeauth.Handshake, role string) error {
	msg, err := hs.Write([]byte(role))
	if err != nil {
		return err
	}
	if len(msg) > 63 {
		return errNodeProof
	}
	frame := append([]byte{nodeFinishedCapsule, byte(len(msg))}, msg...)
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}
func readNodeFinished(r io.Reader, hs nodeauth.Handshake, role string) error {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != nodeFinishedCapsule || hdr[1] > 63 {
		return errNodeProof
	}
	msg := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return err
	}
	plain, err := hs.Read(msg)
	defer clear(plain)
	if err != nil || string(plain) != role {
		return errNodeProof
	}
	return nil
}
