// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/wgtransport"
)

var (
	ErrQueueFull   = errors.New("QUIC-IP bounded send queue is full")
	ErrUnknownPeer = errors.New("QUIC-IP peer is not configured or is unavailable")
	ErrIdentity    = errors.New("QUIC-IP configured local public key does not match the active node identity")
)

const packetBudget = 8 << 20

type Counters struct {
	SentPackets         atomic.Uint64
	ReceivedPackets     atomic.Uint64
	SendQueueDrops      atomic.Uint64
	SendErrors          atomic.Uint64
	EnqueueWaits        atomic.Uint64
	FastPackets         atomic.Uint64
	ReceiveQueueDrops   atomic.Uint64
	FragmentedPackets   atomic.Uint64
	MalformedFrames     atomic.Uint64
	Connections         atomic.Uint64
	HandshakeErrors     atomic.Uint64
	RawPacketsDropped   atomic.Uint64
	RawBytesSent        atomic.Uint64
	RawBytesReceived    atomic.Uint64
	RawWriteBatches     atomic.Uint64
	RawBatchPackets     atomic.Uint64
	HTTP3Requests       atomic.Uint64
	HTTP3PublicRequests atomic.Uint64
	HTTP3PublicPages    atomic.Uint64
	HTTP3Tunnels        atomic.Uint64
	HTTP3Rejected       atomic.Uint64
	HTTP3Datagrams      atomic.Uint64
	TCPStreams          atomic.Uint64
	TCPBytesSent        atomic.Uint64
	TCPBytesReceived    atomic.Uint64
}

type Backend struct {
	factory       *Factory
	host          wgtransport.Host
	bind          carrierBind
	mu            sync.Mutex
	eventMu       sync.Mutex // serialize host notifications across actor replacement
	closed        bool
	active        atomic.Pointer[generation]
	identityOK    atomic.Bool
	authEpoch     atomic.Uint64 // invalidates anonymous in-flight authentication on any revocation
	identityEpoch atomic.Uint64 // invalidates queued work across local identity changes
	networkUp     atomic.Bool
	counters      Counters
	timing        sessionTiming
	tcpStreams    sync.Map // *tcpStreamConn -> struct{}; retained until FIN acknowledgment
	serverHintsMu sync.RWMutex
	serverHints   map[[32]byte]*atomic.Uint32
}
type carrierBind struct{ b *Backend }

type generation struct {
	b         *Backend
	ctx       context.Context
	cancel    context.CancelFunc
	transport *quic.Transport
	listener  *quic.Listener
	pc        net.PacketConn
	bridge    *bindPacketConn
	h3        *http3State
	peersMu   sync.Mutex
	peers     map[[32]byte]*peer
	rx        chan received
	workers   sync.WaitGroup
	txBytes   atomic.Int64
	rxBytes   atomic.Int64
	port      uint16
}

type received struct {
	data  []byte
	ep    *endpoint
	peer  *peer
	stamp lifecycleStamp
}
type packetBuffer struct {
	small [2048]byte
	data  []byte
	stamp lifecycleStamp
}

var packetPool = sync.Pool{New: func() any { return new(packetBuffer) }}

func acquirePacket(data []byte) *packetBuffer {
	p := packetPool.Get().(*packetBuffer)
	if len(data) <= len(p.small) {
		p.data = p.small[:len(data)]
	} else {
		p.data = make([]byte, len(data))
	}
	copy(p.data, data)
	return p
}
func releasePacket(p *packetBuffer) { p.data = nil; packetPool.Put(p) }

type peer struct {
	lastActivity     atomic.Int64
	sendMu           sync.Mutex
	queueMu          sync.RWMutex // final queue drain waits for in-flight enqueues
	scratch          [1500]byte
	connectingPacket atomic.Bool
	g                *generation
	ctx              context.Context
	cancel           context.CancelFunc
	done             chan struct{}
	cfg              peerConfig
	ep               atomic.Pointer[endpoint]
	tx               chan *packetBuffer
	mu               sync.Mutex
	session          *session
	dialing          chan struct{}
	disabled         atomic.Bool
	retired          atomic.Bool   // actor was evicted; it can never be revived
	epoch            atomic.Uint64 // changes on explicit reset/revocation, not ordinary reconnect
	nextID           atomic.Uint32
}
type datagramChannel interface {
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type session struct {
	tcpActive atomic.Int64
	nextRefresh atomic.Int64
	created     time.Time
	q           *quic.Conn
	dgram       datagramChannel
	// Raw packets do not touch the reassembly lock. Capsule fragments and
	// QUIC DATAGRAM fragments share this bounded state when HTTP/3 is used.
	fragmentMu sync.Mutex
	frames     reassembler
	preferred  bool
	outgoing   bool
	stamp      lifecycleStamp
}

func (f *Factory) New(h wgtransport.Host) (wgtransport.Backend, error) {
	if h.Bind == nil {
		return nil, errors.New("QUIC requires a host Bind")
	}
	if h.PeerAllowed == nil {
		return nil, errors.New("native QUIC IP requires live host peer authorization")
	}
	if h.Logf == nil {
		h.Logf = logger.Discard
	}
	if f.cfg.IO == "udp" && h.ListenPacket == nil {
		return nil, errors.New("independent QUIC UDP requires a host-protected ListenPacket hook")
	}
	b := &Backend{timing: defaultSessionTiming(), factory: f, host: h}
	if err := b.autoTrustReady(); err != nil {
		return nil, err
	}
	b.initServerHints()
	b.bind.b = b
	b.networkUp.Store(true)
	return b, nil
}
func (b *Backend) peerAllowed(k [32]byte) bool {
	return b.host.PeerAllowed != nil && b.host.PeerAllowed(k)
}
func (b *Backend) notify(k [32]byte, state wgtransport.SessionState) {
	if b.host.SessionChanged != nil {
		b.host.SessionChanged(k, state)
	}
}

func (b *Backend) Bind() conn.Bind     { return &b.bind }
func (b *Backend) Counters() *Counters { return &b.counters }
func (b *Backend) Close() error        { return b.stop(true) }
func (b *Backend) LocalIdentityChanged(k [32]byte) {
	valid := k != ([32]byte{}) && k == b.localNodeKey()
	old := b.identityOK.Swap(valid)
	if old != valid {
		b.identityEpoch.Add(1)
	}
	if old && !valid {
		b.resetConnections("local identity changed")
	}
}
func (b *Backend) PeerRemoved(k [32]byte) {
	b.authEpoch.Add(1)
	g := b.active.Load()
	if g == nil {
		b.forgetServerHint(k)
		return
	}
	g.peersMu.Lock()
	p := g.peers[k]
	// Drop the old metadata before any session callback can block. A concurrent
	// re-add may create a new hint slot; never delete that replacement afterward.
	b.forgetServerHint(k)
	g.peersMu.Unlock()
	if p != nil {
		p.resetSession("peer removed or reset", true)
	}
}
func (b *Backend) NetworkChanged(up, rebind bool) {
	b.networkUp.Store(up)
	if rebind && b.factory.cfg.IO == "magicsock" {
		b.resetConnections("host network rebound")
	}
}
func (b *Backend) resetConnections(reason string) {
	g := b.active.Load()
	if g == nil {
		return
	}
	g.peersMu.Lock()
	ps := make([]*peer, 0, len(g.peers))
	for _, p := range g.peers {
		ps = append(ps, p)
	}
	g.peersMu.Unlock()
	for _, p := range ps {
		p.closeSession(reason)
	}
}
func (p *peer) publishState(state wgtransport.SessionState) {
	p.g.b.eventMu.Lock()
	defer p.g.b.eventMu.Unlock()
	if p.retired.Load() || p.g.ctx.Err() != nil || p.g.b.active.Load() != p.g {
		return
	}
	p.mu.Lock()
	live := p.session != nil && p.session.q.Context().Err() == nil
	p.mu.Unlock()
	if live {
		state = wgtransport.SessionEstablished
	} else if state == wgtransport.SessionEstablished {
		state = wgtransport.SessionExpired
	}
	p.g.b.notify(p.cfg.key, state)
}

func (p *peer) closeSession(reason string) {
	p.resetSession(reason, false)
}

func (p *peer) resetSession(reason string, disable bool) {
	p.mu.Lock()
	if disable {
		p.disabled.Store(true)
	}
	p.epoch.Add(1) // queued packets belong to the pre-reset peer, even if re-added
	s := p.session
	p.session = nil
	p.mu.Unlock()
	if s != nil {
		s.q.CloseWithError(0, reason)
		p.publishState(wgtransport.SessionExpired)
	}
}

func (c *carrierBind) BatchSize() int { return c.b.host.Bind.BatchSize() }
func (c *carrierBind) SetMark(mark uint32) error {
	if c.b.factory.cfg.IO == "udp" && mark != 0 {
		return errors.New("SO_MARK on independent QUIC sockets is not supported by this adapter")
	}
	return c.b.host.Bind.SetMark(mark)
}
func (c *carrierBind) Close() error { return c.b.stop(false) }

func (c *carrierBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return c.open(port, 0, false)
}

// OpenIP opts into caller-owned buffers that may grow while preserving each
// receive function's original generation and cancellation boundary.
func (c *carrierBind) OpenIP(port uint16, offset int) ([]conn.ReceiveFunc, uint16, error) {
	if offset < 0 || offset > 128 {
		return nil, 0, errors.New("invalid IP headroom")
	}
	return c.open(port, offset, true)
}
func (c *carrierBind) open(port uint16, offset int, grow bool) ([]conn.ReceiveFunc, uint16, error) {
	b := c.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, 0, net.ErrClosed
	}
	if b.active.Load() != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	fns, actual, err := b.host.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &generation{b: b, ctx: ctx, cancel: cancel, peers: make(map[[32]byte]*peer), rx: make(chan received, 1024), port: actual}
	rollback := func() {
		cancel()
		g.closeHTTP3()
		if g.transport != nil {
			g.transport.Close()
		}
		if g.pc != nil {
			g.pc.Close()
		}
		b.host.Bind.Close()
		g.workers.Wait()
	}
	if b.factory.cfg.IO == "udp" {
		udp, err := b.host.ListenPacket(ctx, "udp", b.factory.cfg.Listen)
		if err != nil {
			rollback()
			return nil, 0, err
		}
		// Best effort socket sizing, no global sysctl changes. Native *UDPConn lets
		// quic-go keep recvmmsg/sendmsg GSO/ECN instead of hiding its descriptors.
		if buffered, ok := udp.(interface {
			SetReadBuffer(int) error
			SetWriteBuffer(int) error
		}); ok {
			_ = buffered.SetReadBuffer(4 << 20)
			_ = buffered.SetWriteBuffer(4 << 20)
		}
		g.pc = udp
	} else {
		g.bridge = newBindPacketConn(g)
		g.pc = g.bridge
	}
	// Bound unauthenticated concurrent TLS work. Excess new sources must also
	// validate their address with a Retry before allocating a connection.
	admission := rate.NewLimiter(8, 16)
	var incoming atomic.Int64
	gate := newAdmissionGate(32, 4)
	resetKey := quic.StatelessResetKey(b.factory.resetKey)
	g.transport = &quic.Transport{
		Conn: g.pc, ConnectionIDLength: 8, StatelessResetKey: &resetKey,
		VerifySourceAddress: func(net.Addr) bool { return !admission.Allow() },
		ConnContext: func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
			if incoming.Add(1) > int64(2*maxPeers+16) {
				incoming.Add(-1)
				return nil, errors.New("QUIC connection limit")
			}
			ticket := gate.acquire(admissionSource(info.RemoteAddr))
			if ticket == nil {
				incoming.Add(-1)
				return nil, errors.New("QUIC provisional connection limit")
			}
			context.AfterFunc(ctx, func() { incoming.Add(-1); ticket.release() })
			return context.WithValue(ctx, admissionContextKey{}, ticket), nil
		},
	}
	qc := b.quicConfig()
	listener, err := g.transport.Listen(b.tlsConfig(nil), qc)
	if err != nil {
		rollback()
		return nil, 0, err
	}
	g.listener = listener
	if b.factory.cfg.HTTP3 {
		if err := g.initHTTP3(); err != nil {
			rollback()
			return nil, 0, err
		}
	}
	// Preserve host discovery/DERP processing even when QUIC uses its own socket.
	for _, fn := range fns {
		g.workers.Add(1)
		go g.readHost(fn)
	}
	g.workers.Add(1)
	go g.accept()
	g.workers.Add(1)
	go g.maintainSessions()
	b.active.Store(g)
	if grow {
		return []conn.ReceiveFunc{func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			return g.receivePackets(bufs, sizes, eps, offset, true)
		}}, actual, nil
	}
	return []conn.ReceiveFunc{g.receive}, actual, nil
}

func (b *Backend) quicConfig() *quic.Config {
	streams, uni := int64(-1), int64(-1)
	if b.factory.cfg.HTTP3 {
		streams, uni = 16, 8
	}
	if b.factory.cfg.TCPStreams { streams = 256 }
	cfg := &quic.Config{
		EnableDatagrams: true, HandshakeIdleTimeout: 8 * time.Second, MaxIdleTimeout: 60 * time.Second,
		KeepAlivePeriod: 20 * time.Second, InitialPacketSize: b.factory.cfg.InitialPacketSize,
		MaxIncomingStreams: streams, MaxIncomingUniStreams: uni, Allow0RTT: false,
		MaxStreamReceiveWindow: 128 << 10, MaxConnectionReceiveWindow: 1 << 20,
	}
	if b.factory.cfg.TCPStreams {
		// TCP payload is carried by reliable QUIC streams, not by the inner
		// TCP stack. Receive windows must cover a real WAN bandwidth-delay
		// product; credit is bounded and allocated only as streams consume it.
		cfg.InitialStreamReceiveWindow = 1 << 20
		cfg.MaxStreamReceiveWindow = 16 << 20
		cfg.InitialConnectionReceiveWindow = 4 << 20
		cfg.MaxConnectionReceiveWindow = 32 << 20
	}
	// The released dependency is required at compile time. Never silently
	// ship Reno when the advertised application-limited BBR fixes are absent.
	if b.factory.cfg.BBRv3 {
		cfg.EnableBBRv3CongestionControl()
	} else {
		cfg.EnableBBRCongestionControl()
	}
	return cfg
}

func (b *Backend) stop(final bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if final {
		b.closed = true
	}
	g := b.active.Swap(nil)
	if g == nil {
		return b.host.Bind.Close()
	}
	// Send CONNECTION_CLOSE while the carrier is still usable. Closing the
	// PacketConn first silently discards that notification and leaves remote
	// TCP stream readers waiting for the idle timeout instead of EOF/error.
	g.peersMu.Lock()
	peers := make([]*peer, 0, len(g.peers))
	for _, p := range g.peers { peers = append(peers, p) }
	g.peersMu.Unlock()
	for _, p := range peers {
		p.mu.Lock()
		s := p.session
		p.mu.Unlock()
		if s != nil { _ = s.q.CloseWithError(0, "transport stopped") }
	}
	// Cancellation retires peer actors and may clear p.session. It must
	// follow the close notification rather than racing the snapshot above.
	g.cancel()
	g.closeHTTP3()
	// Cancel the external reader before asking QUIC to join its workers.
	g.pc.Close()
	g.transport.Close()
	err := b.host.Bind.Close()
	// Synchronize with any Send that entered peer creation before cancel.
	g.peersMu.Lock()
	g.peersMu.Unlock()
	g.workers.Wait()
	return err
}

func (c *carrierBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	k, err := parseKey(s)
	if err != nil {
		return nil, err
	}
	if _, err := c.b.automaticPeer(k); err != nil {
		return nil, err
	}
	base, err := c.b.host.Bind.ParseEndpoint(s)
	if err != nil {
		return nil, err
	}
	// Endpoint lifetime can outlast a Bind generation; it resolves the current
	// per-peer actor lazily on Send, preserving Close/Open semantics.
	return &endpoint{Endpoint: base, b: c.b, key: k}, nil
}

func (c *carrierBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b := c.b
	if !b.identityOK.Load() {
		return ErrIdentity
	}
	if !b.networkUp.Load() {
		return errors.New("QUIC-IP network is down")
	}
	g := b.active.Load()
	if g == nil {
		return net.ErrClosed
	}
	e, ok := ep.(*endpoint)
	if !ok || e == nil || e.b != b {
		return conn.ErrWrongEndpointType
	}
	if !b.peerAllowed(e.key) {
		return ErrUnknownPeer
	}
	if len(bufs) > c.BatchSize() || offset < 0 {
		return errors.New("invalid WG send batch/offset")
	}
	p, err := g.peer(e.key, e.Endpoint)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		if offset > len(buf) || len(buf)-offset == 0 || len(buf)-offset > maxPacket {
			return errors.New("invalid WG packet length")
		}
	}
	// Once authenticated, send directly from the borrowed WG batch. quic-go
	// copies a datagram before returning, so an extra packet copy and actor
	// queue are unnecessary. Its bounded queue supplies congestion backpressure.
	p.sendMu.Lock()
	p.mu.Lock()
	s := p.session
	p.mu.Unlock()
	if s != nil && s.q.Context().Err() == nil && !p.disabled.Load() && !p.connectingPacket.Load() && len(p.tx) == 0 {
		defer p.sendMu.Unlock()
		for _, buf := range bufs {
			if err := p.sendPacket(s, buf[offset:], p.scratch[:]); err != nil {
				b.counters.SendErrors.Add(1)
				return err
			}
			b.counters.FastPackets.Add(1)
		}
		return nil
	}
	p.sendMu.Unlock()
	return p.enqueue(bufs, offset)
}

func (p *peer) enqueue(bufs [][]byte, offset int) error {
	g, b := p.g, p.g.b
	p.queueMu.RLock()
	defer p.queueMu.RUnlock()
	if p.retired.Load() {
		return ErrUnknownPeer
	}
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	stamp := p.lifecycleStamp()
	for _, buf := range bufs {
		data := buf[offset:]
		if g.txBytes.Add(int64(len(data))) > packetBudget {
			g.txBytes.Add(-int64(len(data)))
			b.counters.SendQueueDrops.Add(1)
			return ErrQueueFull
		}
		packet := acquirePacket(data)
		packet.stamp = stamp
		select {
		case <-p.ctx.Done():
			g.txBytes.Add(-int64(len(data)))
			releasePacket(packet)
			return net.ErrClosed
		case p.tx <- packet:
		default:
			// Avoid dropping whole IP batches during short QUIC pacing stalls.
			// Backpressure is bounded; no timer/allocation on the normal path.
			b.counters.EnqueueWaits.Add(1)
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case p.tx <- packet:
				timer.Stop()
			case <-p.ctx.Done():
				timer.Stop()
				g.txBytes.Add(-int64(len(data)))
				releasePacket(packet)
				return net.ErrClosed
			case <-timer.C:
				g.txBytes.Add(-int64(len(data)))
				releasePacket(packet)
				b.counters.SendQueueDrops.Add(1)
				return ErrQueueFull
			}
		}
	}
	return nil
}

func (g *generation) peer(k [32]byte, base conn.Endpoint) (*peer, error) {
	// Steady-state packets must not rebuild automatic origins or allocate
	// handshake metadata. Resolve it only when creating/reviving an actor.
	if !g.b.peerAllowed(k) {
		return nil, ErrUnknownPeer
	}
	g.peersMu.Lock()
	if g.ctx.Err() != nil {
		g.peersMu.Unlock()
		return nil, net.ErrClosed
	}
	existing := g.peers[k]
	g.peersMu.Unlock()
	if existing != nil && existing.retired.Load() {
		return nil, ErrUnknownPeer
	}
	if existing != nil && !existing.disabled.Load() {
		existing.touch()
		return existing, nil
	}
	cfg, err := g.b.automaticPeer(k)
	if err != nil {
		return nil, err
	}
	if base == nil {
		var err error
		base, err = g.b.host.Bind.ParseEndpoint(hex.EncodeToString(k[:]))
		if err != nil {
			return nil, err
		}
	}
	g.peersMu.Lock()
	if g.ctx.Err() != nil {
		g.peersMu.Unlock()
		return nil, net.ErrClosed
	}
	if p := g.peers[k]; p != nil {
		g.peersMu.Unlock()
		if p.retired.Load() {
			return nil, ErrUnknownPeer
		}
		if p.disabled.Load() {
			refreshStamp := p.lifecycleStamp()
			// Never acquire host magicsock locks while holding the carrier map
			// lock: peer-removal callbacks may arrive in the opposite direction.
			fresh, err := g.b.host.Bind.ParseEndpoint(hex.EncodeToString(k[:]))
			if err != nil {
				return nil, err
			}
			if !g.b.peerAllowed(k) {
				return nil, ErrUnknownPeer
			}
			g.peersMu.Lock()
			if g.peers[k] != p || p.retired.Load() {
				g.peersMu.Unlock()
				return g.peer(k, fresh)
			}
			if g.ctx.Err() != nil {
				g.peersMu.Unlock()
				return nil, net.ErrClosed
			}
			p.mu.Lock()
			if p.epoch.Load() != refreshStamp.peer || g.b.identityEpoch.Load() != refreshStamp.identity || !g.b.identityOK.Load() {
				p.mu.Unlock()
				g.peersMu.Unlock()
				return nil, ErrUnknownPeer
			}
			p.ep.Store(&endpoint{Endpoint: fresh, b: g.b, key: k})
			p.disabled.Store(false)
			p.mu.Unlock()
			g.b.ensureServerHint(k)
			g.peersMu.Unlock()
		}
		return p, nil
	}
	if len(g.peers) >= maxPeers {
		// Automatic peers accumulate across node-key rotations and removals.
		// Reclaim only a revoked actor, preserving every live peer and leaving
		// old packet/session references permanently invalid. Cancellation also
		// stops a pending dial before the worker drains its bounded send queue.
		for oldKey, old := range g.peers {
			if old.disabled.Load() && !old.retired.Load() {
				old.retired.Store(true)
				old.cancel()
				delete(g.peers, oldKey)
				g.b.serverHintsMu.Lock()
				delete(g.b.serverHints, oldKey)
				g.b.serverHintsMu.Unlock()
				break
			}
		}
		if len(g.peers) >= maxPeers {
			g.peersMu.Unlock()
			return nil, errors.New("active H3 peer limit reached")
		}
	}
	defer g.peersMu.Unlock()
	g.b.ensureServerHint(k)
	ctx, cancel := context.WithCancel(g.ctx)
	p := &peer{g: g, ctx: ctx, cancel: cancel, done: make(chan struct{}), cfg: cfg, tx: make(chan *packetBuffer, g.b.factory.cfg.QueuePackets)}
	p.touch()
	p.ep.Store(&endpoint{Endpoint: base, b: g.b, key: k})
	g.peers[k] = p
	g.workers.Add(1)
	go p.run()
	return p, nil
}

func (g *generation) accept() {
	defer g.workers.Done()
	for {
		q, err := g.listener.Accept(g.ctx)
		if err != nil {
			return
		}
		if g.h3 != nil {
			armAdmissionDeadline(q, g.b.timing.authTimeout)
			g.workers.Add(1)
			go func() { defer g.workers.Done(); _ = g.h3.server.ServeQUICConn(q) }()
			continue
		}
		if !g.b.identityOK.Load() {
			q.CloseWithError(1, "inactive node identity")
			continue
		}
		key, err := g.b.factory.verify(q.ConnectionState().TLS, nil)
		if err != nil {
			g.b.counters.HandshakeErrors.Add(1)
			q.CloseWithError(1, "untrusted peer")
			continue
		}
		p, err := g.peer(key, nil)
		if err != nil {
			q.CloseWithError(1, "peer not available")
			continue
		}
		p.install(q, false)
	}
}

// On simultaneous H3 dials, prefer the ordinary node as TLS client when the
// authenticated declarations differ. Symmetric/unknown pairs keep the stable
// key-based rule. This arbitrates already-established candidates; it never
// starts or resets a healthy connection merely to change its fingerprint.
func (p *peer) preferredOutgoing(hint uint32) bool {
	if p.g.b.factory.cfg.TCPStreams { return !p.g.b.factory.cfg.Server }
	if p.g.b.factory.cfg.HTTP3 && hint != serverUnknown && hint <= serverYes && p.g.b.factory.cfg.Server != (hint == serverYes) {
		return !p.g.b.factory.cfg.Server
	}
	local := p.g.b.localNodeKey()
	return bytes.Compare(local[:], p.cfg.key[:]) < 0
}

func (p *peer) install(q *quic.Conn, outgoing bool) *session {
	return p.installChannel(q, outgoing, q)
}

func (p *peer) installChannel(q *quic.Conn, outgoing bool, channel datagramChannel, authenticatedServerHint ...uint32) *session {
	return p.installBoundChannel(q, outgoing, channel, nil, authenticatedServerHint...)
}

func (p *peer) installBoundChannel(q *quic.Conn, outgoing bool, channel datagramChannel, attempt *lifecycleStamp, authenticatedServerHint ...uint32) *session {
	state := q.ConnectionState()
	if !state.SupportsDatagrams.Local || !state.SupportsDatagrams.Remote {
		q.CloseWithError(1, "QUIC DATAGRAM required")
		return nil
	}
	hint := p.g.b.peerServerHint(p.cfg.key)
	if len(authenticatedServerHint) == 1 {
		hint = authenticatedServerHint[0]
	}
	preferredOutgoing := p.preferredOutgoing(hint)
	preferred := preferredOutgoing == outgoing
	ns := &session{created: time.Now(), q: q, dgram: channel, preferred: preferred, outgoing: outgoing, stamp: p.lifecycleStamp()}
	if attempt != nil {
		ns.stamp = *attempt
	}
	p.mu.Lock()
	old := p.session
	if p.g.ctx.Err() != nil || q.Context().Err() != nil || !p.stampValid(ns.stamp) {
		p.mu.Unlock()
		q.CloseWithError(0, "closed")
		return nil
	}
	// A fresh connection in the same deterministic direction must supersede
	// the old one (remote restart/rebind). Rejecting it until idle timeout can
	// produce an endless successful-TLS-but-no-data reconnect loop.
	if old != nil && old.q.Context().Err() == nil && old.outgoing == preferredOutgoing && !preferred {
		p.mu.Unlock()
		q.CloseWithError(0, "duplicate connection")
		return old
	}
	p.session = ns
	p.g.workers.Add(1)
	p.mu.Unlock()
	if old != nil {
		time.AfterFunc(p.g.b.timing.overlap, func() { old.q.CloseWithError(0, "session replaced") })
	}
	p.touch()
	releaseAdmission(q)
	p.g.b.counters.Connections.Add(1)
	p.publishState(wgtransport.SessionEstablished)
	go p.receiveSession(ns)
	return ns
}

func (p *peer) getSession() (*session, error) { return p.getSessionReplacing(nil) }
func (p *peer) getSessionReplacing(replace *session) (*session, error) {
	return p.getSessionContext(p.ctx, replace)
}
func (p *peer) getSessionContext(parent context.Context, replace *session) (*session, error) {
	if err := parent.Err(); err != nil { return nil, err }
	p.mu.Lock()
	if s := p.session; s != nil && s.q.Context().Err() == nil && (replace == nil || s != replace) {
		p.mu.Unlock()
		return s, nil
	}
	if p.dialing != nil {
		if replace != nil {
			p.mu.Unlock()
			return replace, nil
		}
		wait := p.dialing
		p.mu.Unlock()
		select {
		case <-p.ctx.Done():
			return nil, net.ErrClosed
		case <-parent.Done():
			return nil, parent.Err()
		case <-wait:
			return p.getSessionContext(parent, nil)
		}
	}
	p.dialing = make(chan struct{})
	wait := p.dialing
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.dialing = nil; close(wait); p.mu.Unlock() }()
	if !p.g.b.identityOK.Load() {
		return nil, ErrIdentity
	}
	if p.retired.Load() {
		return nil, ErrUnknownPeer
	}
	if !p.g.b.peerAllowed(p.cfg.key) {
		return nil, ErrUnknownPeer
	}
	if replace == nil {
		p.publishState(wgtransport.SessionHandshake)
	}
	var remote net.Addr = p.cfg.address
	if p.g.bridge != nil {
		remote = &bindAddr{ep: p.ep.Load().Endpoint}
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	stopOnRetire := context.AfterFunc(p.ctx, cancel)
	defer stopOnRetire()
	attempt := p.lifecycleStamp()
	tlsConfig := p.g.b.tlsConfig(&p.cfg.key)
	if p.cfg.http3URL != nil {
		tlsConfig.ServerName = http3ClientHelloServerName(p.cfg.http3URL)
	}
	cfg := p.g.b.quicConfig()
	if profile := p.g.b.browserProfileForPeer(p.cfg.key, true); profile != "" {
		cfg.ClientHelloProfile = profile
	}
	q, err := p.g.transport.Dial(ctx, remote, tlsConfig, cfg)
	if err != nil {
		p.g.b.counters.HandshakeErrors.Add(1)
		if replace == nil {
			p.publishState(wgtransport.SessionExpired)
		}
		return nil, err
	}
	if p.g.b.factory.cfg.HTTP3 {
		return p.openHTTP3Context(ctx, q, attempt)
	}
	s := p.install(q, true)
	if s == nil {
		return nil, net.ErrClosed
	}
	return s, nil
}

func (p *peer) run() {
	defer p.g.workers.Done()
	defer close(p.done)
	defer p.closeSession("peer actor stopped")
	defer func() {
		p.queueMu.Lock()
		defer p.queueMu.Unlock()
		for {
			select {
			case packet := <-p.tx:
				p.g.txBytes.Add(-int64(len(packet.data)))
				releasePacket(packet)
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-p.ctx.Done():
			return
		case packet := <-p.tx:
			p.connectingPacket.Store(true)
			if p.stampValid(packet.stamp) {
				s, err := p.getSession()
				if err == nil {
					p.sendMu.Lock()
					if p.stampValid(packet.stamp) {
						err = p.sendPacket(s, packet.data, p.scratch[:])
					} else {
						p.g.b.counters.SendQueueDrops.Add(1)
					}
					p.sendMu.Unlock()
				}
				if err != nil && p.g.ctx.Err() == nil {
					p.g.b.counters.SendErrors.Add(1)
					// At most one diagnostic per failed handshake, never log packet bytes.
					if s == nil {
						p.g.b.host.Logf("quic-wg: peer %x handshake failed: %v", p.cfg.key[:4], err)
					}
				}
			} else {
				p.g.b.counters.SendQueueDrops.Add(1)
			}
			p.g.txBytes.Add(-int64(len(packet.data)))
			releasePacket(packet)
			p.connectingPacket.Store(false)
		}
	}
}

func (p *peer) sendPacket(s *session, packet, scratch []byte) error {
	p.touch()
	if !p.stampValid(s.stamp) {
		return ErrUnknownPeer
	}
	var tooLarge *quic.DatagramTooLargeError
	limit := 1150
	if len(packet)+1 <= len(scratch) {
		scratch[0] = frameRaw
		copy(scratch[1:], packet)
		clampTCPMSS(scratch[1:len(packet)+1], p.g.b.factory.cfg.TCPMSS)
		err := s.dgram.SendDatagram(scratch[:len(packet)+1])
		if err == nil {
			p.g.b.counters.SentPackets.Add(1)
			return nil
		}
		if !errors.As(err, &tooLarge) {
			return err
		}
		limit = int(tooLarge.MaxDatagramPayloadSize)
	}
	// No IP MTU is silently lowered. Fragment only when the current QUIC path
	// cannot carry the whole encrypted WG message. Sender retains no retransmit
	// state; QUIC DATAGRAM and the inner protocols retain their UDP semantics.
	if limit > len(scratch) {
		limit = len(scratch)
	}
	if limit <= fragmentHeader {
		return errors.New("QUIC DATAGRAM limit too small")
	}
	id := p.nextID.Add(1)
	for offset := 0; offset < len(packet); {
		n := min(limit-fragmentHeader, len(packet)-offset)
		scratch[0] = frameFragment
		binary.BigEndian.PutUint32(scratch[1:5], id)
		binary.BigEndian.PutUint16(scratch[5:7], uint16(len(packet)))
		binary.BigEndian.PutUint16(scratch[7:9], uint16(offset))
		copy(scratch[fragmentHeader:], packet[offset:offset+n])
		err := s.dgram.SendDatagram(scratch[:fragmentHeader+n])
		if err != nil {
			return err
		}
		offset += n
	}
	p.g.b.counters.FragmentedPackets.Add(1)
	p.g.b.counters.SentPackets.Add(1)
	return nil
}

func (p *peer) receiveSession(s *session) {
	defer p.g.workers.Done()
	defer s.q.CloseWithError(0, "datagram receiver stopped")
	defer func() {
		p.mu.Lock()
		current := p.session == s
		if current {
			p.session = nil
		}
		p.mu.Unlock()
		if current {
			p.publishState(wgtransport.SessionExpired)
		}
	}()
	if capsules, ok := s.dgram.(interface{ StartCapsules(func([]byte)) }); ok {
		capsules.StartCapsules(func(data []byte) { p.deliverFrame(s, data) })
	}
	for {
		data, err := s.dgram.ReceiveDatagram(p.ctx)
		if err != nil {
			return
		}
		p.deliverFrame(s, data)
	}
}

// deliverFrame is shared with the infrequent HTTP Capsule reader. In both
// cases packets cross the identical live authorization and bounded IP queue.
func (p *peer) deliverFrame(s *session, data []byte) {
	if s.q.Context().Err() != nil || !p.stampValid(s.stamp) {
		return
	}
	p.touch()
	var packet []byte
	var err error
	if len(data) > 1 && data[0] == frameRaw && len(data)-1 <= maxPacket {
		packet = data[1:]
	} else {
		s.fragmentMu.Lock()
		packet, err = s.frames.consume(data, time.Now())
		s.fragmentMu.Unlock()
	}
	if err != nil {
		p.g.b.counters.MalformedFrames.Add(1)
		return
	}
	if packet == nil {
		return
	}
	if p.g.rxBytes.Add(int64(len(packet))) > packetBudget {
		p.g.rxBytes.Add(-int64(len(packet)))
		p.g.b.counters.ReceiveQueueDrops.Add(1)
		return
	}
	select {
	case p.g.rx <- received{data: packet, ep: p.ep.Load(), peer: p, stamp: s.stamp}:
		p.g.b.counters.ReceivedPackets.Add(1)
	case <-p.g.ctx.Done():
		p.g.rxBytes.Add(-int64(len(packet)))
	default:
		p.g.rxBytes.Add(-int64(len(packet)))
		p.g.b.counters.ReceiveQueueDrops.Add(1)
	}
}

func (g *generation) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	return g.receivePackets(bufs, sizes, eps, 0, false)
}
func (g *generation) receivePackets(bufs [][]byte, sizes []int, eps []conn.Endpoint, offset int, grow bool) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || len(eps) < len(bufs) {
		return 0, errors.New("invalid receive batch")
	}
	for i := range bufs {
		sizes[i] = 0
		eps[i] = nil
	}
	take := func(i int, r received) {
		g.rxBytes.Add(-int64(len(r.data)))
		if grow && len(bufs[i]) < offset+len(r.data) {
			bufs[i] = make([]byte, offset+len(r.data))
		}
		if r.peer == nil || !r.peer.stampValid(r.stamp) || offset+len(r.data) > len(bufs[i]) {
			g.b.counters.ReceiveQueueDrops.Add(1)
			return
		}
		sizes[i] = copy(bufs[i][offset:], r.data)
		eps[i] = r.ep
	}
	select {
	case <-g.ctx.Done():
		return 0, net.ErrClosed
	case r := <-g.rx:
		take(0, r)
	}
	n := 1
	for n < len(bufs) {
		select {
		case r := <-g.rx:
			take(n, r)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

// endpoint preserves host cookie identity and only forwards peer verification
// callbacks when the inner WG identity agrees with the pinned TLS peer.
type endpoint struct {
	conn.Endpoint
	b   *Backend
	key [32]byte
}

// AuthenticatedPeerKey is meaningful only on the TLS-authenticated carrier
// receive path. Native IP authorization still checks CURRENT host policy.
func (e *endpoint) AuthenticatedPeerKey() [32]byte    { return e.key }
func (e *endpoint) UnderlyingEndpoint() conn.Endpoint { return e.Endpoint }
func (e *endpoint) InitiationMessagePublicKey(k [32]byte) {
	if k != e.key {
		return
	}
	if p, ok := e.Endpoint.(conn.InitiationAwareEndpoint); ok {
		p.InitiationMessagePublicKey(k)
	}
}
func (e *endpoint) FromPeer(k [32]byte) {
	if k != e.key {
		e.b.PeerRemoved(e.key)
		return
	}
	if p, ok := e.Endpoint.(conn.PeerAwareEndpoint); ok {
		p.FromPeer(k)
	}
}

var _ wgtransport.Backend = (*Backend)(nil)
var _ wgtransport.PeerLifecycle = (*Backend)(nil)
var _ wgtransport.NetworkLifecycle = (*Backend)(nil)
var _ conn.Bind = (*carrierBind)(nil)
var _ conn.PeerAwareEndpoint = (*endpoint)(nil)
