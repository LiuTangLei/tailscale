// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

const http3AuthScheme = "Peer "
const http3AuthLabel = "EXPORTER-HTTP3-CONNECT-IP-Peer-Auth-v1"

// HTTP/3 uses ordinary server-authenticated TLS, without CertificateRequest.
// Tunnel clients additionally prove possession of a separately pinned key in
// an encrypted Authorization header. The signature covers a TLS exporter and
// the exact request target; a proof captured on one connection is unusable on
// any other. This is a private authorization scheme, not an RFC 9421 signature.
// It is deliberately NOT a replacement for the live Tailnet/source-IP policy.
type tlsExporter func(string, []byte, int) ([]byte, error)

func requestBinding(cs *tls.ConnectionState, r *http.Request, exporter ...tlsExporter) ([]byte, error) {
	if cs == nil || cs.Version != tls.VersionTLS13 || cs.NegotiatedProtocol != "h3" || r.URL == nil {
		return nil, errors.New("HTTP/3 TLS 1.3 required for peer authentication")
	}
	context := sha256.Sum256([]byte(r.Method + "\n" + r.Proto + "\n" + r.Host + "\n" + r.URL.EscapedPath() + "?" + r.URL.RawQuery))
	if len(exporter) > 1 || (len(exporter) == 1 && exporter[0] == nil) {
		return nil, errors.New("invalid TLS exporter")
	}
	if len(exporter) == 1 {
		return exporter[0](http3AuthLabel, context[:], 32)
	}
	return cs.ExportKeyingMaterial(http3AuthLabel, context[:], 32)
}

func (f *Factory) http3Authorization(cs *tls.ConnectionState, r *http.Request, exporter ...tlsExporter) (string, error) {
	binding, err := requestBinding(cs, r, exporter...)
	if err != nil {
		return "", err
	}
	defer clear(binding)
	signer, ok := f.cert.PrivateKey.(crypto.Signer)
	if !ok {
		return "", errors.New("TLS identity cannot sign peer authorization")
	}
	digest := sha256.Sum256(binding)
	var opts crypto.SignerOpts = crypto.SHA256
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		opts = crypto.Hash(0)
	}
	sig, err := signer.Sign(rand.Reader, digest[:], opts)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(f.cert.Certificate[0]) + "." + base64.RawURLEncoding.EncodeToString(sig)
	if len(encoded) > 12<<10 {
		return "", errors.New("peer authorization certificate is too large")
	}
	return http3AuthScheme + encoded, nil
}

func (f *Factory) verifyHTTP3Authorization(cs *tls.ConnectionState, r *http.Request, exporter ...tlsExporter) ([32]byte, error) {
	var zero [32]byte
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 12<<10 || !strings.HasPrefix(values[0], http3AuthScheme) {
		return zero, errors.New("missing peer authorization")
	}
	certPart, sigPart, ok := strings.Cut(strings.TrimPrefix(values[0], http3AuthScheme), ".")
	if !ok {
		return zero, errors.New("invalid peer authorization")
	}
	der, err := base64.RawURLEncoding.DecodeString(certPart)
	if err != nil {
		return zero, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return zero, err
	}
	if err := validCertificate(cert); err != nil {
		return zero, err
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	peer, ok := f.byPin[pin]
	if !ok {
		return zero, errors.New("untrusted authorization key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return zero, err
	}
	binding, err := requestBinding(cs, r, exporter...)
	if err != nil {
		return zero, err
	}
	defer clear(binding)
	digest := sha256.Sum256(binding)
	valid := false
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(pub, digest[:], sig)
	case ed25519.PublicKey:
		valid = ed25519.Verify(pub, digest[:], sig)
	case *rsa.PublicKey:
		valid = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
	}
	if !valid {
		return zero, errors.New("invalid connection-bound peer signature")
	}
	return peer, nil
}
