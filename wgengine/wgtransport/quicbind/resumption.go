// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const resumeAuthorization = "TailnetResume-v1"
const resumeReplyHeader = "Tailnet-Resume"

var errResumeRejected = errors.New("HTTP/3 resumption was not authorized")

type resumptionContextKey struct{}
type resumptionContext struct {
	mu                                           sync.Mutex
	resumed                                      *resumeIdentity
	authorized                                   *resumeIdentity
	resumedAuthEpoch, resumedIdentityEpoch       uint64
	authorizedAuthEpoch, authorizedIdentityEpoch uint64
}

func (b *Backend) initResumption() {
	if b.tickets.Load() != nil {
		return
	}
	store := newMemoryTicketStore()
	if path := b.factory.cfg.TicketJournal; path != "" {
		config, _ := json.Marshal(b.factory.cfg)
		config = append(config, []byte("resume-v1/h3-datagram=1/connect=1/headers=16384")...)
		config = append(config, b.factory.cert.Certificate[0]...)
		config = append(config, b.factory.cfg.AuthenticationSecret[:]...)
		persistent, err := openServerTicketStore(path, sha256.Sum256(config))
		if err == nil {
			store = persistent
		} else {
			b.host.Logf("http3-ip: %v; using memory-only tickets", ticketStoreError(err))
		}
	}
	b.tickets.Store(store)
}
func (b *Backend) clientSessionCache(peer [32]byte) *peerSessionCache {
	b.resumptionMu.Lock()
	defer b.resumptionMu.Unlock()
	if b.clientSessions == nil {
		b.clientSessions = make(map[[32]byte]*peerSessionCache)
	}
	cache := b.clientSessions[peer]
	if cache == nil {
		if len(b.clientSessions) >= maxResumptionTickets {
			for key, old := range b.clientSessions {
				old.clear()
				delete(b.clientSessions, key)
				break
			}
		}
		cache = new(peerSessionCache)
		b.clientSessions[peer] = cache
	}
	return cache
}
func (b *Backend) forgetResumption(peer [32]byte) {
	b.resumptionMu.Lock()
	defer b.resumptionMu.Unlock()
	if store := b.tickets.Load(); store != nil {
		store.revoke(peer)
	}
	for key, cache := range b.clientSessions {
		if peer == ([32]byte{}) || peer == key {
			cache.clear()
			delete(b.clientSessions, key)
		}
	}
}
func (b *Backend) resumeAllowed(identity resumeIdentity) bool {
	if !b.identityOK.Load() || identity.Local != b.localNodeKey() || identity.Peer == ([32]byte{}) || !b.peerAllowed(identity.Peer) {
		return false
	}
	if pin, ok := b.factory.peers[identity.Peer]; ok && pin.pin != ([32]byte{}) && pin.pin != identity.Pin {
		return false
	}
	return true
}
func (b *Backend) resumingTLSConfig() *tls.Config {
	base := b.tlsConfig(nil)
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		state, ok := hello.Context().Value(resumptionContextKey{}).(*resumptionContext)
		if !ok {
			return nil, errors.New("QUIC resumption context is unavailable")
		}
		cfg := base.Clone()
		cfg.GetConfigForClient = nil
		cfg.WrapSession = func(_ tls.ConnectionState, session *tls.SessionState) ([]byte, error) {
			b.resumptionMu.Lock()
			defer b.resumptionMu.Unlock()
			state.mu.Lock()
			identity := state.authorized
			authEpoch, identityEpoch := state.authorizedAuthEpoch, state.authorizedIdentityEpoch
			state.mu.Unlock()
			store := b.tickets.Load()
			if identity == nil || store == nil || authEpoch != b.authEpoch.Load() || identityEpoch != b.identityEpoch.Load() || !b.resumeAllowed(*identity) {
				// TLS can issue only one ticket. Do not tear down an otherwise
				// established channel when authorization changes during issuance;
				// an unrecorded random identity can never be accepted by this store.
				id := make([]byte, 32)
				_, err := rand.Read(id)
				return id, err
			}
			session.EarlyData = true
			return store.issue(*identity, session)
		}
		cfg.UnwrapSession = func(id []byte, _ tls.ConnectionState) (*tls.SessionState, error) {
			b.resumptionMu.Lock()
			defer b.resumptionMu.Unlock()
			authEpoch, identityEpoch := b.authEpoch.Load(), b.identityEpoch.Load()
			store := b.tickets.Load()
			if store == nil {
				return nil, nil
			}
			session, identity := store.take(id)
			if session == nil || !b.resumeAllowed(identity) {
				return nil, nil
			}
			state.mu.Lock()
			state.resumed = &identity
			state.resumedAuthEpoch, state.resumedIdentityEpoch = authEpoch, identityEpoch
			state.mu.Unlock()
			return session, nil
		}
		return cfg, nil
	}
	return base
}
func (b *Backend) resumedIdentity(q *quic.Conn, r *http.Request) (resumeIdentity, error) {
	var zero resumeIdentity
	values := r.Header.Values("Authorization")
	if len(values) != 1 || values[0] != resumeAuthorization {
		return zero, errResumeRejected
	}
	state, ok := q.Context().Value(resumptionContextKey{}).(*resumptionContext)
	if !ok {
		return zero, errResumeRejected
	}
	state.mu.Lock()
	identity := state.resumed
	authEpoch, identityEpoch := state.resumedAuthEpoch, state.resumedIdentityEpoch
	state.mu.Unlock()
	if identity == nil || authEpoch != b.authEpoch.Load() || identityEpoch != b.identityEpoch.Load() || !b.resumeAllowed(*identity) {
		return zero, errResumeRejected
	}
	return *identity, nil
}
func (b *Backend) issueAuthorizedTicket(q *quic.Conn, identity resumeIdentity, attempt lifecycleStamp, authEpoch uint64) {
	state, ok := q.Context().Value(resumptionContextKey{}).(*resumptionContext)
	if !ok || !b.resumeAllowed(identity) {
		return
	}
	store := b.tickets.Load()
	if store == nil {
		return
	}
	store.mu.Lock()
	enabled := !store.disabled
	store.mu.Unlock()
	// A failed journal must not keep advertising unusable replacement tickets
	// and adding a rejected early attempt to every subsequent reconnect.
	if !enabled {
		return
	}
	state.mu.Lock()
	state.authorized = &identity
	state.authorizedAuthEpoch, state.authorizedIdentityEpoch = authEpoch, attempt.identity
	state.mu.Unlock()
	if err := q.SendSessionTicket(); err != nil {
		b.host.Logf("http3-ip: could not issue authenticated resumption ticket: %v", err)
	}
}
func awaitTLS(ctx context.Context, q *quic.Conn) error {
	select {
	case <-q.HandshakeComplete():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-q.Context().Done():
		return context.Cause(q.Context())
	}
}

// Only the tunnel request is early data. Arbitrary UDP/TCP business traffic
// starts after the server accepts it and the client verifies TLS completion.
func (p *peer) openResumedHTTP3(ctx context.Context, q *quic.Conn, attempt lifecycleStamp, setup *connectionSetupStats) (session *session, err error) {
	setup.Stage = "resumption"
	started := time.Now()
	defer func() {
		setup.AuthMicros = time.Since(started).Microseconds()
		if err != nil {
			q.CloseWithError(1, "HTTP/3 resumption failed")
		}
	}()
	return p.openEarlyTunnel(ctx, q, attempt)
}
