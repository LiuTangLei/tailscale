package quicbind

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const tcpStreamsHeader = "Connect-IP-TCP-Streams"

var ErrTCPStreamDenied = errors.New("HTTP/3 TCP target is not served or stream authentication was rejected")

type reliableStream interface {
	io.ReadWriteCloser
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	WaitWriteAcknowledged(context.Context) error
}

// DrainTCPStreams must be called before a one-shot caller exits. QUIC Close
// queues FIN; only its acknowledgment proves the stream is drained.
func (b *Backend) DrainTCPStreams(ctx context.Context) error {
	var result error
	b.tcpStreams.Range(func(key, _ any) bool {
		c := key.(*tcpStreamConn)
		select {
		case <-ctx.Done(): result = ctx.Err()
		case <-c.drained: result = c.drainErr
		}
		return result == nil
	})
	return result
}

// DialTCPStream opens an HTTP/3 CONNECT DATA stream on the same authenticated
// QUIC connection used by CONNECT-IP. Peer identity, application credential and
// revocation are NOT inferred from a Host header or from TLS certificate TOFU.
func (b *Backend) DialTCPStream(ctx context.Context, key [32]byte, dst netip.AddrPort) (net.Conn, error) {
	if !b.factory.cfg.TCPStreams || !dst.IsValid() || dst.Port() == 0 {
		return nil, errors.New("H3 TCP streams are unavailable or the target is invalid")
	}
	if !b.identityOK.Load() || !b.peerAllowed(key) { return nil, ErrUnknownPeer }
	g := b.active.Load()
	if g == nil { return nil, net.ErrClosed }
	base, err := b.host.Bind.ParseEndpoint(fmtKey(key))
	if err != nil { return nil, err }
	p, err := g.peer(key, base)
	if err != nil { return nil, err }
	s, err := p.getSessionContext(ctx, nil)
	if err != nil { return nil, err }
	if !s.outgoing {
		s, err = p.getSessionContext(ctx, s)
		if err != nil { return nil, err }
	}
	channel, ok := s.dgram.(*http3Channel)
	if !ok || channel.client == nil || !channel.tcpStreams {
		return nil, errors.New("peer does not support authenticated HTTP/3 TCP streams; upgrade both H3 endpoints")
	}
	stream, err := channel.client.OpenRequestStream(ctx)
	if err != nil { return nil, err }
	stop := context.AfterFunc(ctx, func(){ stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	_ = stream.SetDeadline(time.Now().Add(10*time.Second))
	abort := func(err error) (net.Conn, error) {
		stream.CancelRead(1); stream.CancelWrite(1)
		if ctx.Err() != nil { err = ctx.Err() }
		return nil, err
	}
	u := &url.URL{Scheme: "https", Host: dst.String()}
	req := &http.Request{Method: http.MethodConnect, Host: dst.String(), URL: u, Header: make(http.Header)}
	if err := stream.SendRequestHeader(req); err != nil { return abort(err) }
	response, err := stream.ReadResponse()
	if err != nil { return abort(err) }
	if response.StatusCode != http.StatusOK || response.Header.Get(tcpStreamsHeader) != "1" {
		return abort(ErrTCPStreamDenied)
	}
	if !stop() { return abort(ctx.Err()) }
	if err := ctx.Err(); err != nil { return abort(err) }
	if !p.stampValid(s.stamp) { return abort(ErrUnknownPeer) }
	_ = stream.SetDeadline(time.Time{})
	local := net.TCPAddrFromAddrPort(netip.AddrPortFrom(b.factory.cfg.TCPNodeAddress(b.localNodeKey()), 0))
	return b.newTCPConn(p, s, stream, local, net.TCPAddrFromAddrPort(dst)), nil
}

func fmtKey(key [32]byte) string {
	const digits = "0123456789abcdef"
	var buf [64]byte
	for i, b := range key { buf[i*2],buf[i*2+1] = digits[b>>4],digits[b&15] }
	return string(buf[:])
}

func (g *generation) tcpSession(q *quic.Conn) (*peer, *session) {
	g.peersMu.Lock()
	defer g.peersMu.Unlock()
	for _, p := range g.peers {
		p.mu.Lock()
		s := p.session
		p.mu.Unlock()
		if s != nil && s.q == q && p.stampValid(s.stamp) { return p, s }
	}
	return nil, nil
}

func (g *generation) handleTCPStream(w http.ResponseWriter, r *http.Request) {
	deny := func(){ g.b.counters.HTTP3Rejected.Add(1); http.NotFound(w,r) }
	if g.b.factory.cfg.TCPHandler == nil || !g.b.identityOK.Load() || r.TLS == nil {
		deny(); return
	}
	q, ok := r.Context().Value(h3ConnKey{}).(*quic.Conn)
	if !ok { deny(); return }
	dst, err := netip.ParseAddrPort(r.Host)
	if err != nil || dst.Port() == 0 || !dst.IsValid() || (r.URL != nil && (r.URL.RawQuery != "" || r.URL.Path != "")) {
		deny(); return
	}
	p, s := g.tcpSession(q)
	if p == nil { deny(); return }
	handler := g.b.factory.cfg.TCPHandler(p.cfg.key, dst)
	if handler == nil || !p.stampValid(s.stamp) { deny(); return }
	w.Header().Set(tcpStreamsHeader,"1")
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil { return }
	stream := w.(http3.HTTPStreamer).HTTPStream()
	remote := net.TCPAddrFromAddrPort(netip.AddrPortFrom(g.b.factory.cfg.TCPNodeAddress(p.cfg.key), 0))
	c := g.b.newTCPConn(p, s, stream, net.TCPAddrFromAddrPort(dst), remote)
	// HTTPStream transfers stream ownership to the application. Do not make
	// http3.Server.Close wait on an arbitrary embedding callback (the IP
	// stack also dispatches those independently). Closing QUIC still aborts
	// all stream I/O; application-owned work must manage its own lifetime.
	go func() {
		defer c.Close()
		handler(c)
	}()
}
