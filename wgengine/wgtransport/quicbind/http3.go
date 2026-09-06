// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Normal HTTP datagrams use CONNECT-IP context 0 (RFC 9484). Context 2 is
// allocated by the CONNECT client for our explicitly negotiated, bounded
// fragmentation extension. Never send the private fragment format to a peer
// that did not echo the extension. QUIC and HTTP/3 wire formats remain standard.
const fragmentHeaderName = "Connect-IP-Fragmentation"
const fragmentHeaderValue = "v1; context=2"
const publicPage = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Welcome</title></head><body><main><h1>Welcome</h1><p>This service is online.</p></main></body></html>\n"

type h3ConnKey struct{}
type http3State struct {
	server   *http3.Server
	tcp      *http.Server
	listener net.Listener
	mu       sync.Mutex
	tunnels  map[*quic.Conn]bool
}

func parseHTTP3URL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return nil, errors.New("http3_url must be an absolute https URL with a path and no credentials or fragment")
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return nil, errors.New("http3_url must use ASCII URI encoding")
		}
	}
	if strings.ContainsAny(s, "{}") {
		return nil, errors.New("http3_url must be expanded, not a URI template")
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid HTTP/3 origin port")
		}
	}
	return u, nil
}

func (g *generation) initHTTP3() error {
	h := &http3State{tunnels: make(map[*quic.Conn]bool)}
	h.server = &http3.Server{
		EnableDatagrams: true, MaxHeaderBytes: 16 << 10, IdleTimeout: 2 * time.Minute,
		Handler:     http.HandlerFunc(g.handleHTTP3),
		ConnContext: func(ctx context.Context, q *quic.Conn) context.Context { return context.WithValue(ctx, h3ConnKey{}, q) },
	}
	g.h3 = h
	if addr := g.b.factory.cfg.HTTP3TCPListen; addr != "" {
		if g.b.host.ListenTCP == nil {
			return errors.New("HTTP/3 public HTTPS listener requires host-protected ListenTCP")
		}
		ln, err := g.b.host.ListenTCP(g.ctx, "tcp", addr)
		if err != nil {
			return err
		}
		h.listener = ln
		h.tcp = &http.Server{Handler: http.HandlerFunc(g.servePublic), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{g.b.factory.cert}},
		}
		g.workers.Add(1)
		go func() {
			defer g.workers.Done()
			if err := h.tcp.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				g.b.host.Logf("http3-ip: public HTTPS listener stopped: %v", err)
			}
		}()
	}
	return nil
}
func (g *generation) closeHTTP3() {
	if g.h3 == nil {
		return
	}
	_ = g.h3.server.Close()
	if g.h3.tcp != nil {
		_ = g.h3.tcp.Close()
	}
	if g.h3.listener != nil {
		_ = g.h3.listener.Close()
	}
}

// Public GET/HEAD requests need no client certificate and can be viewed by a
// normal browser. There is no forwarding, redirect-to-target or open proxy.
func (g *generation) servePublic(w http.ResponseWriter, r *http.Request) {
	origin := g.b.factory.http3URL
	if origin == nil || r.Host != origin.Host || (r.Method != "GET" && r.Method != "HEAD") || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.ProtoMajor == 3 {
		g.b.counters.HTTP3PublicPages.Add(1)
	}
	if r.ProtoMajor == 3 {
		g.b.counters.HTTP3PublicRequests.Add(1)
	}
	port := origin.Port()
	if port == "" {
		port = "443"
	}
	w.Header().Set("Alt-Svc", `h3=":`+port+`"; ma=86400`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(publicPage)))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == "GET" {
		_, _ = io.WriteString(w, publicPage)
	}
}

func (g *generation) handleHTTP3(w http.ResponseWriter, r *http.Request) {
	g.b.counters.HTTP3Requests.Add(1)
	if r.Method != http.MethodConnect {
		g.servePublic(w, r)
		return
	}
	deny := func(code int) { g.b.counters.HTTP3Rejected.Add(1); http.Error(w, http.StatusText(code), code) }
	u := g.b.factory.http3URL
	if r.Proto != "connect-ip" || r.Host != u.Host || r.URL.EscapedPath() != u.EscapedPath() || r.URL.RawQuery != u.RawQuery {
		deny(http.StatusNotFound)
		return
	}
	q, ok := r.Context().Value(h3ConnKey{}).(*quic.Conn)
	if !ok || r.TLS == nil || !g.b.identityOK.Load() {
		deny(http.StatusNotFound)
		return
	}
	k, err := g.b.factory.verifyHTTP3Authorization(r.TLS, r)
	if err != nil || !g.b.peerAllowed(k) {
		deny(http.StatusNotFound)
		return
	}
	peerServerHint, err := parseServerHint(r.Header)
	if err != nil {
		deny(http.StatusBadRequest)
		return
	}
	if r.Header.Get(http3.CapsuleProtocolHeader) != "?1" || len(r.Header.Values(http3.CapsuleProtocolHeader)) != 1 {
		deny(http.StatusBadRequest)
		return
	}
	settings, ok := w.(http3.Settingser)
	if !ok {
		deny(http.StatusInternalServerError)
		return
	}
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	select {
	case <-settings.ReceivedSettings():
	case <-r.Context().Done():
		return
	case <-timer.C:
		deny(http.StatusRequestTimeout)
		return
	}
	if !settings.Settings().EnableDatagrams || !q.ConnectionState().SupportsDatagrams.Remote {
		deny(http.StatusBadRequest)
		return
	}
	p, err := g.peer(k, nil)
	if err != nil {
		deny(http.StatusNotFound)
		return
	}
	g.h3.mu.Lock()
	occupied := g.h3.tunnels[q]
	if !occupied {
		g.h3.tunnels[q] = true
	}
	g.h3.mu.Unlock()
	if occupied {
		deny(http.StatusConflict)
		return
	}
	defer func() { g.h3.mu.Lock(); delete(g.h3.tunnels, q); g.h3.mu.Unlock() }()
	fragments := r.Header.Get(fragmentHeaderName) == fragmentHeaderValue && len(r.Header.Values(fragmentHeaderName)) == 1
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	// Only authenticated CONNECT replies advertise this metadata, never
	// public pages or unauthenticated discovery responses.
	w.Header().Set(serverHintHeader, serverHintValue(g.b.factory.cfg.Server))
	if fragments {
		w.Header().Set(fragmentHeaderName, fragmentHeaderValue)
	}
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	stream := w.(http3.HTTPStreamer).HTTPStream()
	channel := newHTTP3Channel(g, q, stream, stream, fragments)
	session := p.installChannel(q, false, channel)
	if session == nil || session.q != q {
		return
	}
	p.rememberServerHint(session, peerServerHint)
	g.b.counters.HTTP3Tunnels.Add(1)
	// The request stream, not an unrelated raw QUIC receive loop, owns the tunnel.
	select {
	case <-q.Context().Done():
	case <-r.Context().Done():
		_ = q.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "request closed")
	case <-g.ctx.Done():
	}
}

func (p *peer) openHTTP3(q *quic.Conn) (_ *session, reterr error) {
	defer func() {
		if reterr != nil {
			p.g.b.counters.HandshakeErrors.Add(1)
			_ = q.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeMessageError), "CONNECT-IP failed")
		}
	}()
	client := (&http3.Transport{EnableDatagrams: true, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}).NewClientConn(q)
	ctx, cancel := context.WithTimeout(p.g.ctx, 10*time.Second)
	defer cancel()
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-q.Context().Done():
		return nil, context.Cause(q.Context())
	}
	s := client.Settings()
	if !s.EnableDatagrams || !s.EnableExtendedConnect {
		return nil, errors.New("HTTP/3 peer did not negotiate DATAGRAM and Extended CONNECT")
	}
	// Stream lifetime is the generation, not the temporary handshake deadline.
	stream, err := client.OpenRequestStream(p.g.ctx)
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	u := p.cfg.http3URL
	req := &http.Request{Method: http.MethodConnect, Proto: "connect-ip", Host: u.Host, URL: u, Header: http.Header{http3.CapsuleProtocolHeader: []string{"?1"}, fragmentHeaderName: []string{fragmentHeaderValue}}}
	tlsState := q.ConnectionState().TLS
	proof, err := p.g.b.factory.http3Authorization(&tlsState, req)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", proof)
	req.Header.Set(serverHintHeader, serverHintValue(p.g.b.factory.cfg.Server))
	if err := stream.SendRequestHeader(req); err != nil {
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		return nil, fmt.Errorf("CONNECT-IP rejected with HTTP %d or missing Capsule-Protocol", response.StatusCode)
	}
	peerServerHint, err := parseServerHint(response.Header)
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	fragments := response.Header.Get(fragmentHeaderName) == fragmentHeaderValue && len(response.Header.Values(fragmentHeaderName)) == 1
	channel := newHTTP3Channel(p.g, q, stream, stream, fragments)
	session := p.installChannel(q, true, channel)
	if session == nil {
		return nil, net.ErrClosed
	}
	if session.q == q {
		p.rememberServerHint(session, peerServerHint)
	}
	p.g.b.counters.HTTP3Tunnels.Add(1)
	return session, nil
}
