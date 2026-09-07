// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package transportprofile manages a daemon-owned next-start packet transport.
// It never restarts a daemon, edits system services, or exports a private key.
package transportprofile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/wgengine/wgtransport"
	"tailscale.com/wgengine/wgtransport/quicbind"
)

const Filename = "packet-transport.json"
const MaxSize = 1 << 20

var ErrConflict = errors.New("transport profile changed; refresh status before confirming")

var (
	errStoredTLSIdentityInvalid     = errors.New("stored TLS identity is invalid")
	errStoredTLSIdentityExpired     = errors.New("stored TLS identity is expired")
	errStoredTLSIdentityNotYetValid = errors.New("stored TLS identity is not yet valid; check the system clock")
	errStoredIdentityMismatch       = errors.New("stored identity card does not match private identity")
)

// Profile contains private key material. Never return or log a Profile through
// LocalAPI. Public returns its sanitized representation. Storage is separate
// from the WG state file, whose contents are never modified here.
type Profile struct {
	Version     int                 `json:"version"`
	Mode        string              `json:"mode"`
	Server      bool                `json:"server,omitempty"`
	AutoTrust   bool                `json:"auto_trust,omitempty"`
	LocalKey    string              `json:"local_public_key,omitempty"`
	Certificate string              `json:"certificate_pem,omitempty"`
	PrivateKey  string              `json:"private_key_pem,omitempty"`
	Identity    *ipn.TransportPeer  `json:"identity,omitempty"`
	Peers       []ipn.TransportPeer `json:"peers"`
}

func Read(root string) (Profile, string, error) {
	p := Profile{Version: 1, Mode: "native", Peers: []ipn.TransportPeer{}}
	if !filepath.IsAbs(root) {
		return p, "0", errors.New("persistent daemon state directory is unavailable")
	}
	path := filepath.Join(root, Filename)
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, "0", nil
	}
	if err != nil {
		return p, "0", err
	}
	if !st.Mode().IsRegular() || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return p, "0", errors.New("transport profile must be a private regular file (mode 0600)")
	}
	if st.Size() > MaxSize {
		return p, "0", errors.New("transport profile exceeds size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return p, "0", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return p, "0", err
	}
	if len(data) > MaxSize {
		return p, "0", errors.New("transport profile exceeds size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, "0", fmt.Errorf("invalid transport profile: %w", err)
	}
	if dec.Decode(new(any)) != io.EOF {
		return p, "0", errors.New("transport profile must contain one JSON object")
	}
	if p.Version != 1 || !ValidMode(p.Mode) {
		return p, "0", errors.New("unsupported transport profile version or mode; refusing fallback")
	}
	sum := sha256.Sum256(data)
	return p, hex.EncodeToString(sum[:]), nil
}

func ValidMode(m string) bool { return m == "native" || m == "quic-ip" || m == "http3-ip" }
func canonicalKey(k string) (string, error) {
	k = strings.TrimPrefix(k, "nodekey:")
	b, err := hex.DecodeString(k)
	if err != nil || len(b) != 32 || bytes.Equal(b, make([]byte, 32)) {
		return "", errors.New("expected a nonzero 32-byte hexadecimal public key or pin")
	}
	return hex.EncodeToString(b), nil
}
func localHTTP3URLForKey(k string) string {
	if len(k) >= 12 {
		return "https://peer-" + k[:12] + ".invalid/.well-known/masque/ip/*/*/"
	}
	return "https://peer-.invalid/.well-known/masque/ip/*/*/"
}
func NewIdentity(p Profile, localKey string) (Profile, error) {
	k, err := canonicalKey(localKey)
	if err != nil {
		return p, err
	}
	if p.Identity != nil {
		// Do not mutate the caller's card on a rejected/CAS-conflicting update.
		card := *p.Identity
		p.Identity = &card
		_, certErr := p.certificate()
		canRenew := p.AutoTrust && p.Mode == "http3-ip"
		if certErr != nil && !(canRenew && errors.Is(certErr, errStoredTLSIdentityExpired)) {
			return p, certErr
		}
		if p.LocalKey != k {
			if !canRenew {
				return p, errors.New("stored identity belongs to a different node; do not reuse it across profiles")
			}
			if card.HTTP3URL == localHTTP3URLForKey(p.LocalKey) {
				card.HTTP3URL = localHTTP3URLForKey(k)
			}
			p.LocalKey, card.PublicKey = k, k
		}
		if certErr == nil {
			return p, nil
		}
		p.Certificate, p.PrivateKey, p.Identity = "", "", nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return p, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return p, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Tailscale packet transport"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return p, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return p, err
	}
	defer clear(keyDER)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return p, err
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	p.LocalKey = k
	p.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	p.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	// An explicit private authority, not an owned domain or public-CA identity.
	// Magicsock chooses the address; the client authenticates the exact SPKI.
	p.Identity = &ipn.TransportPeer{PublicKey: k, SPKISHA256: hex.EncodeToString(pin[:]), HTTP3URL: "https://peer-" + k[:12] + ".invalid/.well-known/masque/ip/*/*/"}
	return p, nil
}
func (p Profile) certificate() (tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(p.Certificate), []byte(p.PrivateKey))
	if err != nil {
		return cert, errStoredTLSIdentityInvalid
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, errStoredTLSIdentityInvalid
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if p.Identity == nil || p.LocalKey != p.Identity.PublicKey || hex.EncodeToString(pin[:]) != p.Identity.SPKISHA256 {
		return cert, errStoredIdentityMismatch
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return cert, errStoredTLSIdentityNotYetValid
	}
	if !now.Before(leaf.NotAfter) {
		return cert, errStoredTLSIdentityExpired
	}
	cert.Leaf = leaf
	return cert, nil
}
func (p Profile) Public(revision string) ipn.TransportControlStatus {
	var identity *ipn.TransportPeer
	if p.Identity != nil {
		card := *p.Identity
		card.Server = p.Server
		identity = &card
	}
	auth := "pinned-key"
	if p.AutoTrust {
		auth = "node-key"
	}
	return ipn.TransportControlStatus{DesiredMode: p.Mode, Server: p.Server, AutoTrust: p.AutoTrust, Authentication: auth, Revision: revision, Identity: identity, Peers: slices.Clone(p.Peers), Available: true}
}
func (p Profile) Factory() (*quicbind.Factory, error) {
	if p.AutoTrust && p.Mode != "http3-ip" {
		return nil, errors.New("automatic node authentication requires HTTP/3")
	}
	if p.Mode == "native" {
		return nil, nil
	}
	if !ValidMode(p.Mode) {
		return nil, errors.New("invalid mode")
	}
	cert, err := p.certificate()
	if err != nil {
		return nil, err
	}
	c := quicbind.Config{Version: 2, Payload: "ip", IO: "magicsock", LocalPublicKey: p.LocalKey, InitialPacketSize: 1400, QueuePackets: 256}
	if p.Mode == "http3-ip" {
		c.HTTP3 = true
		c.Server = p.Server
		if p.Identity != nil {
			c.HTTP3URL = p.Identity.HTTP3URL
		}
		c.AutoTrust = p.AutoTrust
	}
	for _, peer := range p.Peers {
		q := quicbind.PeerConfig{PublicKey: peer.PublicKey, SPKISHA256: peer.SPKISHA256}
		if c.HTTP3 {
			q.HTTP3URL = peer.HTTP3URL
			q.Server = peer.Server
		}
		c.Peers = append(c.Peers, q)
	}
	return quicbind.NewFactoryWithCertificate(c, cert)
}
func (p Profile) Validate(localKey string) error {
	if !ValidMode(p.Mode) || p.Version != 1 {
		return errors.New("invalid profile mode/version")
	}
	if p.AutoTrust && p.Mode != "http3-ip" {
		return errors.New("automatic node authentication requires HTTP/3")
	}
	if p.Mode == "native" {
		return nil
	}
	k, err := canonicalKey(localKey)
	if err != nil {
		return errors.New("transport identity does not match the active node")
	}
	if !p.AutoTrust && p.LocalKey != k {
		return errors.New("transport identity does not match the active node")
	}
	_, err = p.Factory()
	return err
}
func Apply(p Profile, req ipn.TransportControlRequest, localKey string) (Profile, error) {
	switch req.Action {
	case "prepare":
		if req.AutoTrust != nil {
			if *req.AutoTrust && p.Mode != "http3-ip" {
				return p, errors.New("automatic node authentication requires HTTP/3")
			}
			p.AutoTrust = *req.AutoTrust
		}
		return NewIdentity(p, localKey)
	case "add-peer":
		if req.Peer == nil {
			return p, errors.New("peer identity card required")
		}
		if p.Identity == nil {
			return p, errors.New("initialize the local public identity first")
		}
		peer := *req.Peer
		var err error
		peer.PublicKey, err = canonicalKey(peer.PublicKey)
		if err != nil {
			return p, err
		}
		peer.SPKISHA256, err = canonicalKey(peer.SPKISHA256)
		if err != nil {
			return p, err
		}
		if len(peer.Name) > 128 || strings.ContainsAny(peer.Name, "\r\n\x1b") {
			return p, errors.New("invalid peer display name")
		}
		if peer.PublicKey == p.LocalKey || peer.SPKISHA256 == p.Identity.SPKISHA256 {
			return p, errors.New("cannot import own identity")
		}
		for _, old := range p.Peers {
			if old.PublicKey == peer.PublicKey {
				if old == peer {
					return p, nil
				}
				// Updating a public server hint is not TLS key rotation. Keep
				// key, pin, name and origin identity checks otherwise unchanged.
				old.Server = peer.Server
				if old == peer {
					p.Peers = slices.Clone(p.Peers)
					for i := range p.Peers {
						if p.Peers[i].PublicKey == peer.PublicKey {
							p.Peers[i].Server = peer.Server
						}
					}
					return p, p.Validate(localKey)
				}
				return p, errors.New("peer already exists with a different identity; explicitly remove it before trusting a replacement")
			}
			if old.SPKISHA256 == peer.SPKISHA256 {
				return p, errors.New("TLS key must identify exactly one peer")
			}
		}
		if len(p.Peers) >= 256 {
			return p, errors.New("at most 256 trusted peers are supported")
		}
		p.Peers = append(slices.Clone(p.Peers), peer)
		// Validate even a staged native profile's imported URLs/pins against both
		// native-IP config and (when supplied) HTTP/3 configuration.
		check := p
		check.Mode = "quic-ip"
		if _, err := check.Factory(); err != nil {
			return p, err
		}
		if peer.HTTP3URL != "" {
			q := p
			q.Mode = "http3-ip"
			q.Peers = []ipn.TransportPeer{peer}
			if _, err := q.Factory(); err != nil {
				return p, err
			}
		}
	case "remove-peer":
		k, err := canonicalKey(req.PublicKey)
		if err != nil {
			return p, err
		}
		peers := slices.Clone(p.Peers)
		idx := slices.IndexFunc(peers, func(v ipn.TransportPeer) bool { return v.PublicKey == k })
		if idx < 0 {
			return p, errors.New("peer not in the trusted profile")
		}
		p.Peers = slices.Delete(peers, idx, idx+1)
		if p.Mode != "native" && len(p.Peers) == 0 && !p.AutoTrust {
			return p, errors.New("cannot remove last peer from an enabled profile; stage native first")
		}
	case "server":
		if req.Server == nil {
			return p, errors.New("server update requires an explicit true or false")
		}
		p.Server = *req.Server
	case "mode":
		if !ValidMode(req.Mode) {
			return p, errors.New("choose native, quic-ip or http3-ip; WG-over-QUIC is not a production mode")
		}
		p.Mode = req.Mode
		if req.AutoTrust != nil {
			p.AutoTrust = *req.AutoTrust
		} else if req.Mode == "http3-ip" {
			p.AutoTrust = true
		} else {
			p.AutoTrust = false
		}
		if req.Mode == "http3-ip" {
			var err error
			p, err = NewIdentity(p, localKey)
			if err != nil {
				return p, err
			}
		}
	case "validate":
	default:
		return p, errors.New("unknown transport action")
	}
	if err := p.Validate(localKey); err != nil {
		return p, err
	}
	return p, nil
}

// Save needs serialized calls from the owning daemon in addition to CAS. It
// writes one atomic private file, never service units or a shell command.
func Save(root string, p Profile, expected string) (string, error) {
	_, rev, err := Read(root)
	if err != nil {
		return "", err
	}
	if expected == "" || expected != rev {
		return "", ErrConflict
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	if len(data) > MaxSize {
		return "", errors.New("transport profile too large")
	}
	if err := atomicfile.WriteFile(filepath.Join(root, Filename), append(data, '\n'), 0600); err != nil {
		return "", err
	}
	_, rev, err = Read(root)
	return rev, err
}

// LoadForStart does not allocate sockets. Corrupt/expired configuration fails
// closed. An absent file means native; an explicit environment selection is
// handled by the caller and takes precedence over this managed profile.
func (p Profile) renewAutoTrustIdentity() (Profile, error) {
	if !p.AutoTrust || p.Mode != "http3-ip" || p.LocalKey == "" {
		return p, nil
	}
	p.Certificate = ""
	p.PrivateKey = ""
	p.Identity = nil
	return NewIdentity(p, p.LocalKey)
}

func LoadForStart(root string) (wgtransport.Config, string, error) {
	if root == "" {
		return wgtransport.Config{}, "0", nil
	}
	p, rev, err := Read(root)
	if err != nil {
		return wgtransport.Config{}, "", err
	}
	if rev == "0" {
		return wgtransport.Config{}, rev, nil
	}
	if p.Mode == "native" {
		return wgtransport.Config{Mode: wgtransport.Native}, rev, nil
	}
	if p.AutoTrust && p.Mode == "http3-ip" {
		if _, err := p.certificate(); err != nil {
			if !errors.Is(err, errStoredTLSIdentityExpired) {
				return wgtransport.Config{}, "", err
			}
			p, err = p.renewAutoTrustIdentity()
			if err != nil {
				return wgtransport.Config{}, "", err
			}
			if _, err := Save(root, p, rev); err != nil {
				return wgtransport.Config{}, "", err
			}
			_, rev, err = Read(root)
			if err != nil {
				return wgtransport.Config{}, "", err
			}
		}
	}
	f, err := p.Factory()
	if err != nil {
		return wgtransport.Config{}, "", err
	}
	return wgtransport.Config{Mode: f.Mode(), Factory: f}, rev, nil
}
