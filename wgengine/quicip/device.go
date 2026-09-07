// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicip

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/LiuTangLei/wireguard-go/tun"
	"tailscale.com/wgengine/wgtransport"
)

const (
	// Keep Tailscale's normal TUN headroom for packet filters/NAT without
	// introducing a WG header on the wire. These bytes are never transmitted.
	packetOffset = 16
	maxIPPacket  = 65535
)

// Policy must be backed by the CURRENT control-plane snapshots. TLS pins are
// identity bindings, not admission grants; revocation must take effect without
// waiting for QUIC idle timeout. SourceAllowed uses accepted source prefixes
// and longest-prefix ownership, not only the sender's own broad AllowedIPs.
// Callbacks may run concurrently and must not re-enter Device.
type Policy struct {
	PeerAllowed   func([32]byte) bool
	SourceAllowed func([32]byte, netip.Addr) bool
}

type routeFunc func(netip.Addr) ([32]byte, bool)
type stateCallback func([32]byte, wgtransport.SessionState)

// PeerStatus reports tunnel state explicitly as QUIC-IP; no WG handshake time
// is fabricated. Counters count admitted IP bytes, not encrypted UDP bytes.
type PeerStatus struct {
	Key              [32]byte
	TxBytes, RxBytes uint64
	SessionState     wgtransport.SessionState
	LastEstablished  time.Time
}
type Counters struct {
	Malformed    atomic.Uint64
	SourceDenied atomic.Uint64
	PeerDenied   atomic.Uint64
	NoRoute      atomic.Uint64
	SendErrors   atomic.Uint64
	TunErrors    atomic.Uint64
}
type peer struct {
	key      [32]byte
	endpoint atomic.Pointer[endpointBox]
	tx, rx   atomic.Uint64
	// state and last are protected by Device.peersMu, so readers see coherent
	// session transitions rather than last-established surviving a revocation.
	state wgtransport.SessionState
	last  time.Time
}
type endpointBox struct{ ep conn.Endpoint }

// Device is a single-owner, batched TUN<->authenticated-datagram pump. A native
// mode never constructs this type. Exactly one engine owns TUN.Read, avoiding
// competing WG and QUIC readers. Calls Write, not InjectInbound*, so Tailscale's
// ACL, NAT, jailed-peer filtering, netstack dispatch and capture still execute.
type Device struct {
	tun             tun.Device
	bind            conn.Bind
	policy          atomic.Pointer[Policy]
	route           atomic.Pointer[routeFunc]
	local           atomic.Pointer[[32]byte]
	cb              atomic.Pointer[stateCallback]
	peersMu         sync.Mutex
	peers           map[[32]byte]*peer
	eventMu         sync.Mutex
	mu              sync.Mutex
	started, closed bool
	closeOnce       sync.Once
	done            chan struct{}
	stop            chan struct{}
	workers         sync.WaitGroup
	counters        Counters
}

func New(t tun.Device, b conn.Bind) (*Device, error) {
	if t == nil || b == nil {
		return nil, errors.New("native IP engine needs TUN and carrier")
	}
	if t.BatchSize() < 1 || t.BatchSize() > conn.IdealBatchSize || b.BatchSize() < 1 || b.BatchSize() > conn.IdealBatchSize {
		return nil, errors.New("invalid native IP batch size")
	}
	return &Device{tun: t, bind: b, peers: make(map[[32]byte]*peer), done: make(chan struct{}), stop: make(chan struct{})}, nil
}
func (d *Device) Done() <-chan struct{} { return d.done }
func (d *Device) Counters() *Counters   { return &d.counters }
func (d *Device) SetPolicy(p Policy)    { d.policy.Store(&p) }
func (d *Device) SetRouteFunc(fn func(netip.Addr) ([32]byte, bool)) {
	if fn == nil {
		d.route.Store(nil)
		return
	}
	r := routeFunc(fn)
	d.route.Store(&r)
}
func (d *Device) SetStateCallback(fn func([32]byte, wgtransport.SessionState)) {
	if fn == nil {
		d.cb.Store(nil)
		return
	}
	f := stateCallback(fn)
	d.cb.Store(&f)
}
func (d *Device) SetLocalIdentity(k [32]byte) {
	old := d.local.Swap(&k)
	if old != nil && *old == k {
		return
	}
	// Drop cached endpoints/accounting on identity/profile switch. The carrier
	// closes authenticated sessions through its own LocalIdentityChanged hook.
	d.peersMu.Lock()
	d.peers = make(map[[32]byte]*peer)
	d.peersMu.Unlock()
}
func (d *Device) PeerAllowed(k [32]byte) bool {
	local := d.local.Load()
	p := d.policy.Load()
	return local != nil && *local != ([32]byte{}) && k != *local && p != nil && p.PeerAllowed != nil && p.PeerAllowed(k)
}
func (d *Device) getPeer(k [32]byte) *peer {
	d.peersMu.Lock()
	defer d.peersMu.Unlock()
	p := d.peers[k]
	if p == nil {
		p = &peer{key: k}
		d.peers[k] = p
	}
	return p
}

// SyncPeer drops cached endpoint identity. Authorization is never cached here;
// every ingress/egress and new TLS session rechecks live policy.
func (d *Device) SyncPeer(k [32]byte) {
	d.peersMu.Lock()
	p := d.peers[k]
	if p != nil {
		p.endpoint.Store(nil)
	}
	d.peersMu.Unlock()
	if !d.PeerAllowed(k) {
		d.RemovePeer(k)
	}
}
func (d *Device) RemovePeer(k [32]byte) {
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	d.peersMu.Lock()
	_, had := d.peers[k]
	delete(d.peers, k)
	d.peersMu.Unlock()
	if had {
		if cb := d.cb.Load(); cb != nil {
			(*cb)(k, wgtransport.SessionNone)
		}
	}
}
func (d *Device) SessionChanged(k [32]byte, state wgtransport.SessionState) {
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	if state == wgtransport.SessionEstablished && !d.PeerAllowed(k) {
		return
	}
	select {
	case <-d.stop:
		return
	default:
	}
	d.peersMu.Lock()
	p := d.peers[k]
	if p == nil {
		if state == wgtransport.SessionNone || state == wgtransport.SessionExpired {
			d.peersMu.Unlock()
			return
		}
		p = &peer{key: k}
		d.peers[k] = p
	}
	changed := p.state != state
	p.state = state
	if state == wgtransport.SessionEstablished {
		p.last = time.Now()
	} else if state == wgtransport.SessionNone {
		p.last = time.Time{}
		delete(d.peers, k)
	}
	d.peersMu.Unlock()
	if changed {
		if cb := d.cb.Load(); cb != nil {
			(*cb)(k, state)
		}
	}
}
func (d *Device) PeerStatus(k [32]byte) (PeerStatus, bool) {
	d.peersMu.Lock()
	defer d.peersMu.Unlock()
	p := d.peers[k]
	if p == nil {
		return PeerStatus{}, false
	}
	return PeerStatus{Key: k, TxBytes: p.tx.Load(), RxBytes: p.rx.Load(), SessionState: p.state, LastEstablished: p.last}, true
}
func (d *Device) ActivePeers() [][32]byte {
	d.peersMu.Lock()
	defer d.peersMu.Unlock()
	keys := make([][32]byte, 0, len(d.peers))
	for k := range d.peers {
		keys = append(keys, k)
	}
	return keys
}

func (d *Device) Up() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	if d.started {
		return nil
	}
	// Match the host Bind's established Close/Open contract, including magicsock.
	if err := d.bind.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	var fns []conn.ReceiveFunc
	var err error
	grows := false
	if dynamic, ok := d.bind.(interface {
		OpenIP(uint16, int) ([]conn.ReceiveFunc, uint16, error)
	}); ok {
		fns, _, err = dynamic.OpenIP(0, packetOffset)
		grows = true
	} else {
		fns, _, err = d.bind.Open(0)
	}
	if err != nil {
		return err
	}
	if len(fns) == 0 {
		d.bind.Close()
		return errors.New("carrier has no receive functions")
	}
	d.started = true
	for _, fn := range fns {
		d.workers.Add(1)
		go d.receive(fn, grows)
	}
	d.workers.Add(1)
	go d.transmit()
	return nil
}
func (d *Device) Close() {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.stop)
		d.mu.Unlock()
		d.bind.Close()
		d.tun.Close()
		d.workers.Wait()
		d.peersMu.Lock()
		d.peers = make(map[[32]byte]*peer)
		d.peersMu.Unlock()
		close(d.done)
	})
}
func (d *Device) failed() { go d.Close() }

func (d *Device) transmit() {
	defer d.workers.Done()
	read := d.tun.Read
	bufferSize := packetOffset + maxIPPacket
	if dynamic, ok := d.tun.(interface {
		ReadWithBufferGrowth([][]byte, []int, int) (int, error)
	}); ok {
		read = dynamic.ReadWithBufferGrowth
		bufferSize = packetOffset + 2048
	}
	count := d.tun.BatchSize()
	bufs := make([][]byte, count)
	sizes := make([]int, count)
	for i := range bufs {
		bufs[i] = make([]byte, bufferSize)
	}
	batch := make([][]byte, 0, d.bind.BatchSize())
	var target *peer
	var ep conn.Endpoint
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if !d.PeerAllowed(target.key) {
			d.counters.PeerDenied.Add(uint64(len(batch)))
		} else if err := d.bind.Send(batch, ep, packetOffset); err != nil {
			d.counters.SendErrors.Add(uint64(len(batch)))
		} else {
			var total uint64
			for _, b := range batch {
				total += uint64(len(b) - packetOffset)
			}
			target.tx.Add(total)
		}
		batch = batch[:0]
	}
	for {
		n, err := read(bufs, sizes, packetOffset)
		if err != nil {
			select {
			case <-d.stop:
			default:
				d.failed()
			}
			return
		}
		if n < 0 || n > len(bufs) {
			d.failed()
			return
		}
		for i := 0; i < n; i++ {
			size := sizes[i]
			if size <= 0 {
				continue
			}
			if size > maxIPPacket {
				d.counters.Malformed.Add(1)
				continue
			}
			_, dst, err := ParseIP(bufs[i][packetOffset : packetOffset+size])
			if err != nil {
				d.counters.Malformed.Add(1)
				continue
			}
			fn := d.route.Load()
			if fn == nil {
				d.counters.NoRoute.Add(1)
				continue
			}
			k, ok := (*fn)(dst)
			if !ok {
				d.counters.NoRoute.Add(1)
				continue
			}
			if !d.PeerAllowed(k) {
				d.counters.PeerDenied.Add(1)
				continue
			}
			if target == nil || target.key != k || len(batch) == d.bind.BatchSize() {
				flush()
				target = d.getPeer(k)
				ep = nil
			}
			if ep == nil {
				box := target.endpoint.Load()
				if box == nil {
					endpoint, err := d.bind.ParseEndpoint(fmt.Sprintf("%x", k[:]))
					if err != nil {
						d.counters.NoRoute.Add(1)
						continue
					}
					box = &endpointBox{ep: endpoint}
					target.endpoint.Store(box)
				}
				ep = box.ep
			}
			batch = append(batch, bufs[i][:packetOffset+size])
		}
		flush()
		// Refresh identity after control-plane invalidation, including a peer
		// removal and re-add between consecutive TUN batches.
		target = nil
		ep = nil
		select {
		case <-d.stop:
			return
		default:
		}
	}
}

type authenticatedEndpoint interface{ AuthenticatedPeerKey() [32]byte }

func (d *Device) receive(fn conn.ReceiveFunc, grows bool) {
	defer d.workers.Done()
	bufferSize := packetOffset + maxIPPacket
	if grows {
		bufferSize = packetOffset + 2048
	}
	count := d.bind.BatchSize()
	storage := make([][]byte, count)
	data := make([][]byte, count)
	out := make([][]byte, count)
	sizes := make([]int, count)
	eps := make([]conn.Endpoint, count)
	for i := range storage {
		storage[i] = make([]byte, bufferSize)
		data[i] = storage[i][packetOffset:]
	}
	for {
		var n int
		var err error
		if grows {
			n, err = fn(storage, sizes, eps)
			for i := range storage {
				data[i] = storage[i][packetOffset:]
			}
		} else {
			n, err = fn(data, sizes, eps)
		}
		if err != nil {
			select {
			case <-d.stop:
			default:
				d.failed()
			}
			return
		}
		if n < 0 || n > count {
			d.failed()
			return
		}
		accepted := 0
		for i := 0; i < n; i++ {
			size := sizes[i]
			if size <= 0 {
				continue
			}
			if size > len(data[i]) {
				d.counters.Malformed.Add(1)
				continue
			}
			a, ok := eps[i].(authenticatedEndpoint)
			if !ok {
				d.counters.PeerDenied.Add(1)
				continue
			}
			k := a.AuthenticatedPeerKey()
			if !d.PeerAllowed(k) {
				d.counters.PeerDenied.Add(1)
				continue
			}
			src, _, err := ParseIP(data[i][:size])
			if err != nil {
				d.counters.Malformed.Add(1)
				continue
			}
			policy := d.policy.Load()
			if policy == nil || policy.SourceAllowed == nil || !policy.SourceAllowed(k, src) {
				d.counters.SourceDenied.Add(1)
				continue
			}
			// Associate physical endpoints only AFTER authenticated-peer and source-IP
			// checks. Never infer permission from IP address alone.
			if aware, ok := eps[i].(conn.PeerAwareEndpoint); ok {
				aware.FromPeer(k)
			}
			d.getPeer(k).rx.Add(uint64(size))
			out[accepted] = storage[i][:packetOffset+size]
			accepted++
		}
		if accepted > 0 {
			if _, err := d.tun.Write(out[:accepted], packetOffset); err != nil {
				d.counters.TunErrors.Add(1)
			}
			clear(out[:accepted])
		}
		select {
		case <-d.stop:
			return
		default:
		}
	}
}
