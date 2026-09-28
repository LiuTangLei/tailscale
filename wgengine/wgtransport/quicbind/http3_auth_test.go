// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"context"
	"net/http"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3AuthorizationCannotReplayAcrossTLSConnections(t *testing.T) {
	pair := newTestPair(t, "http3-udp")
	pair.open(t)
	a, b := pair.backends[0], pair.backends[1]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dial := func() *quic.Conn {
		cfg := a.factory.tlsConfig(&b.factory.local)
		cfg.ServerName = "quic-ip.test"
		cfg.Certificates = nil
		q, err := a.active.Load().transport.Dial(ctx, a.factory.peers[b.factory.local].address, cfg, a.quicConfig())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = q.CloseWithError(0, "") })
		return q
	}
	request := func() *http.Request {
		u := b.factory.http3URL
		return &http.Request{Method: "CONNECT", Proto: "connect-ip", Host: u.Host, URL: u,
			Header: http.Header{http3.CapsuleProtocolHeader: []string{"?1"}}}
	}
	q1 := dial()
	firstTLS := q1.ConnectionState().TLS
	proof, err := a.factory.http3Authorization(&firstTLS, request())
	if err != nil {
		t.Fatal(err)
	}
	_ = q1.CloseWithError(0, "")

	q2 := dial()
	client := (&http3.Transport{EnableDatagrams: true}).NewClientConn(q2)
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	connect := func(proof string) int {
		str, err := client.OpenRequestStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = str.SetDeadline(time.Now().Add(5 * time.Second))
		r := request()
		r.Header.Set("Authorization", proof)
		if err := str.SendRequestHeader(r); err != nil {
			t.Fatal(err)
		}
		res, err := str.ReadResponse()
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 200 {
			str.CancelRead(0)
			str.CancelWrite(0)
		}
		return res.StatusCode
	}
	if got := connect(proof); got != 404 {
		t.Fatalf("replayed connection proof accepted: %d", got)
	}
	if b.counters.HTTP3Tunnels.Load() != 0 {
		t.Fatal("replay created a tunnel")
	}
	currentTLS := q2.ConnectionState().TLS
	correct, err := a.factory.http3Authorization(&currentTLS, request())
	if err != nil {
		t.Fatal(err)
	}
	if got := connect(correct); got != 200 {
		t.Fatalf("valid connection-bound proof rejected: %d", got)
	}
}
