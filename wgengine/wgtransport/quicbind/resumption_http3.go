// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (p *peer) openEarlyTunnel(parent context.Context, q *quic.Conn, attempt lifecycleStamp) (*session, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(p.ctx, func() { q.CloseWithError(1, "peer actor stopped") })
	defer stop()
	client := (&http3.Transport{EnableDatagrams: true, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}).NewClientConn(q)
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	stream.SetDeadline(time.Now().Add(10 * time.Second))
	// The stateful PSK was issued only after a previous authenticated CONNECT.
	// Its protocol scope fixes H3 DATAGRAM / Extended CONNECT / header limits;
	// incompatible server configurations invalidate the ticket journal.
	u := p.cfg.http3URL
	req := &http.Request{Method: http.MethodConnect, Proto: "connect-ip", Host: u.Host, URL: u, Header: http.Header{
		"Authorization": []string{resumeAuthorization}, http3.CapsuleProtocolHeader: []string{"?1"},
		fragmentHeaderName: []string{fragmentHeaderValue}, serverHintHeader: []string{serverHintValue(p.g.b.factory.cfg.Server)},
	}}
	if p.g.b.factory.cfg.TCPRepair && supportsTCPRepair(q) {
		req.Header.Set(tcpRepairHeader, "v1")
	}
	if err := stream.SendRequestHeader(req); err != nil {
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusTooEarly {
		return nil, errResumeRejected
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(resumeReplyHeader) != "v1" || response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		return nil, fmt.Errorf("HTTP/3 resumption rejected (HTTP %d)", response.StatusCode)
	}
	if err := awaitTLS(ctx, q); err != nil {
		return nil, err
	}
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-q.Context().Done():
		return nil, context.Cause(q.Context())
	}
	settings := client.Settings()
	if !settings.EnableDatagrams || !settings.EnableExtendedConnect || !q.ConnectionState().SupportsDatagrams.Remote {
		return nil, errResumeRejected
	}
	hint, err := parseServerHint(response.Header)
	if err != nil {
		return nil, err
	}
	stream.SetDeadline(time.Time{})
	fragments := response.Header.Get(fragmentHeaderName) == fragmentHeaderValue && len(response.Header.Values(fragmentHeaderName)) == 1
	channel := newHTTP3Channel(p.g, q, stream, stream, fragments)
	channel.enableTCPRepair(p.g.b.factory.cfg.TCPRepair && response.Header.Get(tcpRepairHeader) == "v1" && len(response.Header.Values(tcpRepairHeader)) == 1)
	channel.client = client
	channel.tcpStreams = response.Header.Get(tcpStreamsHeader) == "1" && len(response.Header.Values(tcpStreamsHeader)) == 1
	session := p.installBoundChannel(q, true, channel, &attempt, hint)
	if session == nil {
		return nil, net.ErrClosed
	}
	if session.q == q {
		p.rememberServerHint(session, hint)
	}
	p.g.b.counters.HTTP3Tunnels.Add(1)
	return session, nil
}
