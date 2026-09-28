// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"fmt"
	"net/netip"

	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/LiuTangLei/wireguard-go/device"
	"github.com/LiuTangLei/wireguard-go/tun"
	"go4.org/mem"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/quicip"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgint"
	"tailscale.com/wgengine/wgtransport"
)

// packetEngine is the IP data-plane compatibility boundary. Both implementations
// own one TUN reader and preserve Tailscale's filtered Wrapper.Write path. WG
// encapsulation is an implementation choice, not a prerequisite of QUIC-IP.
// Control-plane route/ACL management stays in userspaceEngine/LocalBackend.
type packetEngine interface {
	Up() error
	Close()
	Done() <-chan struct{}
	ApplyConfig(*wgcfg.Config) error
	SetIdentity(key.NodePrivate) error
	SetPeerConfigFunc(func(key.NodePublic) ([]netip.Prefix, bool))
	SetRouteFunc(func(netip.Addr) (key.NodePublic, bool))
	SetPolicy(func(key.NodePublic) bool, func(key.NodePublic, netip.Addr) bool)
	SetSessionCallback(func(key.NodePublic, PeerWireGuardState))
	CarrierSessionChanged([32]byte, wgtransport.SessionState)
	SyncPeer(key.NodePublic, []netip.Prefix)
	RemovePeer(key.NodePublic)
	ActivePeers() []key.NodePublic
	Status(key.NodePublic) (ipnstate.PeerStatusLite, bool)
	WireGuardPeer(key.NodePublic) (wgint.Peer, bool)
}

// wgPacketEngine uses our Tailscale-compatible AWG fork unchanged. Native mode
// still supplies the original magicsock Bind, with no extra data-plane queues.
type wgPacketEngine struct {
	dev  *device.Device
	logf logger.Logf
}

func (p *wgPacketEngine) Up() error             { return p.dev.Up() }
func (p *wgPacketEngine) Close()                { p.dev.Close() }
func (p *wgPacketEngine) Done() <-chan struct{} { return p.dev.Wait() }
func (p *wgPacketEngine) ApplyConfig(c *wgcfg.Config) error {
	return wgcfg.ApplyAmneziaConfig(p.dev, c.AmneziaWG)
}
func (p *wgPacketEngine) SetIdentity(k key.NodePrivate) error {
	return p.dev.SetPrivateKey(key.NodePrivateAs[device.NoisePrivateKey](k))
}
func (p *wgPacketEngine) SetPeerConfigFunc(fn func(key.NodePublic) ([]netip.Prefix, bool)) {
	p.dev.SetPeerLookupFunc(wgcfg.NewPeerLookupFunc(p.dev.Bind(), p.logf, func(k device.NoisePublicKey) ([]netip.Prefix, bool) { return fn(keyFromRaw(k)) }))
}
func (p *wgPacketEngine) SetRouteFunc(fn func(netip.Addr) (key.NodePublic, bool)) {
	if fn == nil {
		p.dev.SetPeerByIPPacketFunc(nil)
		return
	}
	p.dev.SetPeerByIPPacketFunc(func(_, dst netip.Addr, _ []byte) (device.NoisePublicKey, bool) {
		k, ok := fn(dst)
		return k.Raw32(), ok
	})
}
func (p *wgPacketEngine) SetPolicy(func(key.NodePublic) bool, func(key.NodePublic, netip.Addr) bool) {
}
func (p *wgPacketEngine) SetSessionCallback(fn func(key.NodePublic, PeerWireGuardState)) {
	p.dev.SetSessionStateFunc(func(k device.NoisePublicKey, s device.PeerSessionState) {
		if fn != nil {
			fn(keyFromRaw(k), peerWireGuardStateFromDevice(s))
		}
	})
}
func (p *wgPacketEngine) CarrierSessionChanged([32]byte, wgtransport.SessionState) {}
func (p *wgPacketEngine) SyncPeer(k key.NodePublic, ips []netip.Prefix) {
	if peer, ok := p.dev.LookupActivePeer(k.Raw32()); ok {
		peer.SetAllowedIPs(ips)
	}
}
func (p *wgPacketEngine) RemovePeer(k key.NodePublic) { p.dev.RemovePeer(k.Raw32()) }
func (p *wgPacketEngine) WireGuardPeer(k key.NodePublic) (wgint.Peer, bool) {
	peer, ok := p.dev.LookupActivePeer(k.Raw32())
	if !ok {
		return wgint.Peer{}, false
	}
	return wgint.PeerOf(peer), true
}
func (p *wgPacketEngine) ActivePeers() []key.NodePublic {
	var keys []key.NodePublic
	p.dev.RemoveMatchingPeers(func(k device.NoisePublicKey) bool { keys = append(keys, keyFromRaw(k)); return false })
	return keys
}
func (p *wgPacketEngine) Status(k key.NodePublic) (ipnstate.PeerStatusLite, bool) {
	peer, ok := p.WireGuardPeer(k)
	if !ok {
		return ipnstate.PeerStatusLite{}, false
	}
	return ipnstate.PeerStatusLite{NodeKey: k, TxBytes: int64(peer.TxBytes()), RxBytes: int64(peer.RxBytes()), LastHandshake: peer.LastHandshake(), SessionProtocol: "wireguard"}, true
}

// ipPacketEngine never creates *device.Device. key.NodePrivate is accepted only
// at the old host API boundary; only Public() is supplied to the IP pump.
type ipPacketEngine struct {
	dev      *quicip.Device
	protocol string
}

func newIPPacketEngine(t tun.Device, b conn.Bind, mode ...wgtransport.Mode) (*ipPacketEngine, error) {
	d, err := quicip.New(t, b)
	if err != nil {
		return nil, err
	}
	protocol := string(wgtransport.QUICIP)
	if len(mode) > 0 {
		protocol = string(mode[0])
	}
	return &ipPacketEngine{dev: d, protocol: protocol}, nil
}
func (p *ipPacketEngine) Up() error             { return p.dev.Up() }
func (p *ipPacketEngine) Close()                { p.dev.Close() }
func (p *ipPacketEngine) Done() <-chan struct{} { return p.dev.Done() }
func (p *ipPacketEngine) ApplyConfig(c *wgcfg.Config) error {
	// Do not silently ignore AWG prefs or environment on a native IP engine.
	// In particular, TLS cannot hide or repair an unintended mixed profile.
	effective, err := wgcfg.EffectiveAmneziaConfig(c.AmneziaWG)
	if err != nil {
		return err
	}
	if !effective.IsZero() {
		return fmt.Errorf("quic-ip does not use AWG; clear AmneziaWG preferences/environment before selecting it")
	}
	return nil
}
func (p *ipPacketEngine) SetIdentity(k key.NodePrivate) error {
	var pub [32]byte
	if !k.IsZero() {
		pub = k.Public().Raw32()
	}
	p.dev.SetLocalIdentity(pub)
	return nil
}
func (p *ipPacketEngine) SetPeerConfigFunc(func(key.NodePublic) ([]netip.Prefix, bool)) {}
func (p *ipPacketEngine) SetRouteFunc(fn func(netip.Addr) (key.NodePublic, bool)) {
	if fn == nil {
		p.dev.SetRouteFunc(nil)
		return
	}
	p.dev.SetRouteFunc(func(dst netip.Addr) ([32]byte, bool) { k, ok := fn(dst); return k.Raw32(), ok })
}
func (p *ipPacketEngine) SetPolicy(auth func(key.NodePublic) bool, src func(key.NodePublic, netip.Addr) bool) {
	policy := quicip.Policy{}
	if auth != nil {
		policy.PeerAllowed = func(k [32]byte) bool { return auth(keyFromRaw(k)) }
	}
	if src != nil {
		policy.SourceAllowed = func(k [32]byte, ip netip.Addr) bool { return src(keyFromRaw(k), ip) }
	}
	p.dev.SetPolicy(policy)
}
func (p *ipPacketEngine) SetSessionCallback(fn func(key.NodePublic, PeerWireGuardState)) {
	if fn == nil {
		p.dev.SetStateCallback(nil)
		return
	}
	p.dev.SetStateCallback(func(k [32]byte, s wgtransport.SessionState) { fn(keyFromRaw(k), PeerWireGuardState(s)) })
}
func (p *ipPacketEngine) CarrierSessionChanged(k [32]byte, s wgtransport.SessionState) {
	p.dev.SessionChanged(k, s)
}
func (p *ipPacketEngine) SyncPeer(k key.NodePublic, _ []netip.Prefix) { p.dev.SyncPeer(k.Raw32()) }
func (p *ipPacketEngine) RemovePeer(k key.NodePublic)                 { p.dev.RemovePeer(k.Raw32()) }
func (p *ipPacketEngine) ActivePeers() []key.NodePublic {
	raw := p.dev.ActivePeers()
	keys := make([]key.NodePublic, len(raw))
	for i, k := range raw {
		keys[i] = keyFromRaw(k)
	}
	return keys
}
func (p *ipPacketEngine) WireGuardPeer(key.NodePublic) (wgint.Peer, bool) { return wgint.Peer{}, false }
func (p *ipPacketEngine) Status(k key.NodePublic) (ipnstate.PeerStatusLite, bool) {
	st, ok := p.dev.PeerStatus(k.Raw32())
	if !ok {
		return ipnstate.PeerStatusLite{}, false
	}
	return ipnstate.PeerStatusLite{NodeKey: k, TxBytes: int64(st.TxBytes), RxBytes: int64(st.RxBytes), SessionProtocol: p.protocol, LastSessionEstablished: st.LastEstablished, SessionState: uint8(st.SessionState)}, true
}
func keyFromRaw(k [32]byte) key.NodePublic { return key.NodePublicFromRaw32(mem.B(k[:])) }

var _ packetEngine = (*wgPacketEngine)(nil)
var _ packetEngine = (*ipPacketEngine)(nil)
