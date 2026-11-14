// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// earlyData reports whether tunnel packets may follow a resumed CONNECT
// request without waiting for its answer. The negotiated TCP extensions
// change how packets are framed, so those profiles wait for the response.
func (c Config) earlyData() bool { return !c.TCPStreams && !c.TCPRepair }

// resumeAnswer is the validated content of a resumed CONNECT response.
type resumeAnswer struct {
	hint                                uint32
	fragments, repair, tcpStreams, long bool
}

// openEarlyTunnel sends the resumed CONNECT request as 0-RTT data. early
// reports that the session was installed without waiting for the answer.
// handover means a working session is being replaced: packets keep using it
// until the new one is fully established, which is never slower.
func (p *peer) openEarlyTunnel(parent context.Context, q *quic.Conn, attempt lifecycleStamp, handover bool) (_ *session, early bool, _ error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(p.ctx, func() { q.CloseWithError(1, "peer actor stopped") })
	defer stop()
	client := (&http3.Transport{EnableDatagrams: true, MaxResponseHeaderBytes: 16 << 10, DisableCompression: true}).NewClientConn(q)
	stream, err := client.OpenRequestStream(ctx)
	if err != nil {
		return nil, false, err
	}
	stream.SetDeadline(time.Now().Add(10 * time.Second))
	// The stateful PSK was issued only after a previous authenticated CONNECT.
	// Its protocol scope fixes H3 DATAGRAM / Extended CONNECT / header limits;
	// incompatible server configurations invalidate the ticket journal.
	u := p.cfg.http3URL
	req := &http.Request{Method: http.MethodConnect, Proto: "connect-ip", Host: u.Host, URL: u, Header: http.Header{
		"Authorization": []string{resumeAuthorization}, http3.CapsuleProtocolHeader: []string{"?1"},
		fragmentHeaderName: []string{fragmentHeaderValue}, serverHintHeader: []string{serverHintValue(p.g.b.factory.cfg.Server)},
		sessionLifetimeHeader: []string{sessionLifetimeLong},
	}}
	cache := p.g.b.clientSessionCache(p.cfg.key)
	req.Header.Set(packetSizeHeader, packetSizeValue(p.g.b.factory.cfg.MaxPacketSize, uint16(cache.packetSize.Load())))
	if p.g.b.factory.cfg.TCPRepair && supportsTCPRepair(q) {
		req.Header.Set(tcpRepairHeader, tcpRepairVersion)
	}
	if err := stream.SendRequestHeader(req); err != nil {
		return nil, false, err
	}
	if p.g.b.factory.cfg.earlyData() && !handover && cache.early.Load() {
		// Install now: packets already waiting for this peer leave in the
		// same flight as the request instead of two round trips later. The
		// peer's role was authenticated by the session that issued the ticket.
		channel := newEarlyHTTP3Channel(p.g, q, stream, stream, cache.fragments.Load())
		channel.client = client
		session := p.installBoundChannel(q, true, channel, &attempt)
		if session == nil {
			return nil, true, net.ErrClosed
		}
		if session.q == q {
			// Until the peer answers, assume what it stated last time.
			session.peerPacketSize.Store(cache.peerPacketSize.Load())
			session.provenPacketSize.Store(cache.packetSize.Load())
		}
		p.g.b.counters.HTTP3Tunnels.Add(1)
		p.g.workers.Add(1)
		go func() {
			defer p.g.workers.Done()
			p.confirmEarlyTunnel(q, client, stream, channel, session)
		}()
		return session, true, nil
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, false, err
	}
	answer, err := p.validateResumeResponse(ctx, q, client, response)
	if err != nil {
		return nil, false, err
	}
	stream.SetDeadline(time.Time{})
	channel := newHTTP3Channel(p.g, q, stream, stream, answer.fragments)
	channel.enableTCPRepair(p.g.b.factory.cfg.TCPRepair && answer.repair)
	channel.client = client
	channel.tcpStreams = answer.tcpStreams
	cache.remember(response.Header, answer.fragments)
	session := p.installBoundChannel(q, true, channel, &attempt, answer.hint)
	if session == nil {
		return nil, false, net.ErrClosed
	}
	if session.q == q {
		session.longLived.Store(answer.long)
		cache.usePacketSize(session, response.Header)
		p.rememberServerHint(session, answer.hint)
	}
	p.g.b.counters.HTTP3Tunnels.Add(1)
	return session, false, nil
}

// validateResumeResponse checks the peer's answer to a resumed CONNECT and
// waits for the proof that this is the peer holding the ticket: a completed
// TLS handshake. Every failure that means "this resumption is not usable"
// wraps errResumeRejected, so that the caller falls back to a full handshake.
func (p *peer) validateResumeResponse(ctx context.Context, q *quic.Conn, client *http3.ClientConn, response *http.Response) (resumeAnswer, error) {
	var answer resumeAnswer
	if response.StatusCode == http.StatusTooEarly {
		return answer, errResumeRejected
	}
	if response.StatusCode != http.StatusOK || response.Header.Get(resumeReplyHeader) != "v1" || response.Header.Get(http3.CapsuleProtocolHeader) != "?1" {
		return answer, fmt.Errorf("%w (HTTP %d)", errResumeRejected, response.StatusCode)
	}
	if err := awaitTLS(ctx, q); err != nil {
		return answer, err
	}
	select {
	case <-client.ReceivedSettings():
	case <-ctx.Done():
		return answer, ctx.Err()
	case <-q.Context().Done():
		return answer, context.Cause(q.Context())
	}
	settings := client.Settings()
	if !settings.EnableDatagrams || !settings.EnableExtendedConnect || !q.ConnectionState().SupportsDatagrams.Remote {
		return answer, errResumeRejected
	}
	hint, err := parseServerHint(response.Header)
	if err != nil {
		return answer, fmt.Errorf("%w: %v", errResumeRejected, err)
	}
	one := func(name, value string) bool {
		return response.Header.Get(name) == value && len(response.Header.Values(name)) == 1
	}
	answer = resumeAnswer{
		hint: hint, fragments: one(fragmentHeaderName, fragmentHeaderValue), repair: one(tcpRepairHeader, tcpRepairVersion),
		tcpStreams: one(tcpStreamsHeader, "1"), long: wantsLongSession(response.Header),
	}
	return answer, nil
}

// confirmEarlyTunnel completes an early tunnel in the background. If the peer
// refuses the resumption, the connection is closed, a full handshake is
// started at once (the ticket is spent, and waiting for the next packet would
// only add delay) and the first packets of the refused flight are sent again
// on the new connection.
func (p *peer) confirmEarlyTunnel(q *quic.Conn, client *http3.ClientConn, stream *http3.RequestStream, channel *http3Channel, s *session) {
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()
	response, err := stream.ReadResponse()
	var answer resumeAnswer
	if err == nil {
		answer, err = p.validateResumeResponse(ctx, q, client, response)
	}
	if err != nil {
		refused := errors.Is(err, quic.Err0RTTRejected) || errors.Is(err, errResumeRejected)
		_ = q.CloseWithError(1, "HTTP/3 resumption failed")
		if !refused {
			// The connection ended for another reason (shutdown, revocation,
			// replacement, path failure); ordinary reconnection applies.
			return
		}
		p.g.b.counters.ZeroRTTRejected.Add(1)
		flight := p.takeRejectedEarlyFlight(channel)
		if p.ctx.Err() != nil || p.g.ctx.Err() != nil {
			return
		}
		next, err := p.getSession()
		if err != nil {
			if p.ctx.Err() == nil {
				p.g.b.host.Logf("quic-wg: peer %x handshake after refused resumption failed: %v", p.cfg.key[:4], err)
			}
			return
		}
		p.sendMu.Lock()
		defer p.sendMu.Unlock()
		for _, packet := range flight {
			if p.sendPacket(next, packet, p.scratch[:]) != nil {
				return
			}
			p.g.b.counters.EarlyPacketsResent.Add(1)
		}
		return
	}
	stream.SetDeadline(time.Time{})
	if s.q == q {
		s.longLived.Store(answer.long)
		p.g.b.clientSessionCache(p.cfg.key).usePacketSize(s, response.Header)
		p.rememberServerHint(s, answer.hint)
	}
	p.g.b.clientSessionCache(p.cfg.key).remember(response.Header, answer.fragments)
	channel.confirm(answer.fragments)
	p.g.b.counters.ZeroRTTAccepted.Add(1)
}

// takeRejectedEarlyFlight waits for an in-progress sender to record every
// accepted packet. Close the rejected connection first so a full send queue
// cannot keep the sender blocked while this waits for sendMu.
func (p *peer) takeRejectedEarlyFlight(channel *http3Channel) [][]byte {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	return channel.takeEarly()
}
