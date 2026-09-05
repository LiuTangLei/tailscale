// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wgtransport is the experimental boundary between the WireGuard/AWG
// device and its packet carrier. It does not implement WireGuard, QUIC, peer
// discovery or routing. Native mode preserves the original Bind verbatim.
package wgtransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/types/logger"
)

// Mode selects the outer carrier, independently of the device-wide AWG profile.
type Mode string

const (
	Native Mode = "native"
	QUIC   Mode = "quic" // Requires an explicitly configured, authenticated provider.
)

var (
	ErrUnsupported   = errors.New("WireGuard transport is not available")
	ErrInvalidConfig = errors.New("invalid WireGuard transport configuration")
)

// Config selects a statically linked provider. A zero Config uses Native.
// There is no global registry, runtime plugin loader or automatic fallback.
// Factory may be set by an embedding application when a provider is available.
type Config struct {
	Mode    Mode
	Factory Factory
}

// Factory constructs a provider without opening the supplied Bind. On failure
// it must clean up its own resources and leave the Bind owned by the caller.
// A provider must implement the exact mode requested; downgrades are forbidden.
type Factory interface {
	Mode() Mode
	New(Host) (Backend, error)
}

// Host contains the host-owned packet endpoint and diagnostics. The underlying
// Bind may route over direct UDP, DERP or peer relays. Do not assume its endpoint
// strings are IP:port, that it is a UDP socket, or that a logical peer's physical
// path is stable. A path-aware provider will need an additional host adapter.
type Host struct {
	Bind conn.Bind
	Logf logger.Logf
	// ListenPacket creates host-protected outbound UDP sockets (for example
	// using Tailscale netns marks to avoid recursive exit-node routing). A
	// provider must not replace this with an unprotected global socket.
	ListenPacket func(context.Context, string, string) (net.PacketConn, error)
}

// Backend exposes a WireGuard-compatible Bind and a final shutdown operation.
//
// Bind.Open/Close are repeatable WG lifecycle operations, NOT final shutdown:
// Close must unblock every outstanding receive with net.ErrClosed, and a later
// Open must work. Preserve offset headroom, batch sizes, zero-size receive slots
// and Endpoint identity callbacks. Send buffers are borrowed only for the call;
// an asynchronous backend must copy before returning.
//
// Close cancels and releases all provider resources and must be idempotent. It
// must not wait for the caller to later close a Bind to unblock its own workers.
// The WG device remains responsible for its Bind and TUN lifecycle. The host may
// already have closed the underlying network when final Close is called.
type Backend interface {
	Bind() conn.Bind
	Close() error
}

// PeerLifecycle is an optional backend extension. Calls are serialized with all
// other lifecycle callbacks and final Close. They must return promptly and must
// not call back into the engine or Manager (the engine may hold its WG lock).
// Bind traffic can run concurrently; the backend must synchronize its sessions.
// Only PUBLIC node identity is supplied, never a WireGuard private key.
type PeerLifecycle interface {
	LocalIdentityChanged(publicKey [32]byte)
	PeerRemoved(publicKey [32]byte)
}

// NetworkLifecycle notifies a provider after the host updates/rebinds its
// network. It is NOT a per-peer path-selection API or proof of QUIC migration.
type NetworkLifecycle interface {
	NetworkChanged(up, rebind bool)
}

// Resolve applies the environment only when Mode is unspecified. Invalid and
// unavailable modes fail before the engine allocates TUN/network resources.
func Resolve(c Config, environment string) (Config, error) {
	if c.Mode == "" {
		c.Mode = Mode(strings.TrimSpace(environment))
	}
	if c.Mode == "" {
		c.Mode = Native
	}
	switch c.Mode {
	case Native:
		return c, nil
	case QUIC:
		if isNil(c.Factory) {
			return Config{}, fmt.Errorf("%w: %q (no QUIC provider configured; refusing native fallback)", ErrUnsupported, c.Mode)
		}
		if c.Factory.Mode() != c.Mode {
			return Config{}, fmt.Errorf("%w: requested %q, provider implements %q", ErrInvalidConfig, c.Mode, c.Factory.Mode())
		}
		return c, nil
	default:
		return Config{}, fmt.Errorf("%w: unknown mode %q; WG/AWG profiles are not transport modes", ErrInvalidConfig, c.Mode)
	}
}

// Manager owns provider lifecycle, not the caller's underlying Bind. In Native
// mode Bind returns the exact original object, preserving optional interfaces
// and leaving the packet hot path unchanged. A nil Manager is safe for lifecycle
// calls to accommodate engine construction errors and existing unit fixtures.
type Manager struct {
	mode     Mode
	bind     conn.Bind
	backend  Backend
	mu       sync.Mutex
	closed   bool
	closeErr error
	localKey [32]byte
}

func New(h Host, c Config) (*Manager, error) {
	c, err := Resolve(c, "")
	if err != nil {
		return nil, err
	}
	if isNil(h.Bind) {
		return nil, fmt.Errorf("%w: nil underlying Bind", ErrInvalidConfig)
	}
	m := &Manager{mode: c.Mode, bind: h.Bind}
	if c.Mode == Native {
		return m, nil
	}
	if h.Logf == nil {
		h.Logf = logger.Discard
	}
	b, err := c.Factory.New(h)
	if err != nil {
		if !isNil(b) {
			err = errors.Join(err, b.Close())
		}
		return nil, fmt.Errorf("create %s transport: %w", c.Mode, err)
	}
	if isNil(b) {
		return nil, fmt.Errorf("%w: %s factory returned a nil backend", ErrInvalidConfig, c.Mode)
	}
	bind := b.Bind()
	if isNil(bind) || bind.BatchSize() <= 0 || bind.BatchSize() > conn.IdealBatchSize {
		return nil, errors.Join(fmt.Errorf("%w: %s backend returned an invalid Bind/batch size", ErrInvalidConfig, c.Mode), b.Close())
	}
	m.backend, m.bind = b, bind
	return m, nil
}

func (m *Manager) Bind() conn.Bind { return m.bind }
func (m *Manager) Mode() Mode      { return m.mode }

func (m *Manager) LocalIdentityChanged(k [32]byte) {
	if m == nil || m.backend == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.localKey == k {
		return
	}
	m.localKey = k
	if p, ok := m.backend.(PeerLifecycle); ok {
		p.LocalIdentityChanged(k)
	}
}

func (m *Manager) PeerRemoved(k [32]byte) {
	if m == nil || m.backend == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if p, ok := m.backend.(PeerLifecycle); ok {
		p.PeerRemoved(k)
	}
}

func (m *Manager) NetworkChanged(up, rebind bool) {
	if m == nil || m.backend == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if p, ok := m.backend.(NetworkLifecycle); ok {
		p.NetworkChanged(up, rebind)
	}
}

func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		if m.backend != nil {
			m.closeErr = m.backend.Close()
		}
	}
	return m.closeErr
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(v).IsNil()
	}
	return false
}
