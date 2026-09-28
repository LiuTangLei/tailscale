// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func stalledHTTP3Peer(t *testing.T, maxStreams int64, handler http.Handler) (*peer, <-chan error) {
	t.Helper()
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	client, server := pair.backends[0], pair.backends[1]
	config := server.quicConfig()
	config.MaxIncomingStreams = maxStreams
	listener, err := quic.ListenAddr("127.0.0.1:0", server.tlsConfig(nil), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	h3 := &http3.Server{EnableDatagrams: true, Handler: handler}
	t.Cleanup(func() { _ = h3.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverDone := make(chan error, 1)
	go func() {
		q, err := listener.Accept(ctx)
		if err == nil {
			err = h3.ServeQUICConn(q)
		}
		serverDone <- err
	}()
	if _, _, err := client.Bind().Open(0); err != nil {
		t.Fatal(err)
	}
	pair.bases[0].setRemote(listener.Addr().String())
	p, err := client.active.Load().peer(pair.keys[1].Public().Raw32(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, serverDone
}

func TestHTTP3StreamCreditWaitHasHandshakeDeadline(t *testing.T) {
	// Complete provisional TLS and send valid HTTP/3 SETTINGS, but never grant
	// stream credit. A stalled peer must not pin the sender actor indefinitely.
	p, serverDone := stalledHTTP3Peer(t, -1, nil)
	result := make(chan error, 1)
	go func() {
		_, err := p.getSession()
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("stream-credit wait: %v; want handshake deadline", err)
		}
	case <-time.After(13 * time.Second):
		t.Fatal("stream-credit wait escaped the HTTP/3 handshake deadline")
	}
	p.mu.Lock()
	stuck := p.session != nil || p.dialing != nil
	p.mu.Unlock()
	if stuck || p.g.b.counters.Connections.Load() != 0 {
		t.Fatal("stalled provisional connection retained an actor or installed a session")
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("timed-out provisional QUIC connection was not closed")
	}
}

func TestHTTP3RetirementCancelsProvisionalCONNECT(t *testing.T) {
	entered := make(chan struct{})
	p, serverDone := stalledHTTP3Peer(t, 1, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	result := make(chan error, 1)
	go func() {
		_, err := p.getSession()
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provisional CONNECT did not reach response-header wait")
	}
	// This is the cancellation performed when a revoked actor is reclaimed.
	// No installed session exists yet for closeSession to interrupt.
	p.retired.Store(true)
	p.cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("retired provisional connection installed a session")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retirement left CONNECT blocked until its header deadline")
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("retirement retained the provisional QUIC connection")
	}
}
