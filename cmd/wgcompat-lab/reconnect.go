// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"errors"
	"net/http"
	"sync/atomic"

	"tailscale.com/wgengine/wgtransport"
	"tailscale.com/wgengine/wgtransport/quicbind"
)

// Test-only factory wrapper. It captures the actual backend installed by the
// test engine, without changing production APIs or relying on global factories.
// The loopback admin exercises the same lifecycle notification as a host rebind.
type labReconnectFactory struct {
	factory *quicbind.Factory
	active  atomic.Pointer[quicbind.Backend]
}

func (f *labReconnectFactory) Mode() wgtransport.Mode { return f.factory.Mode() }
func (f *labReconnectFactory) New(h wgtransport.Host) (wgtransport.Backend, error) {
	b, err := f.factory.New(h)
	if err != nil {
		return nil, err
	}
	q, ok := b.(*quicbind.Backend)
	if !ok {
		b.Close()
		return nil, errors.New("unexpected test backend")
	}
	f.active.Store(q)
	return b, nil
}
func (f *labReconnectFactory) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	if f == nil {
		http.Error(w, "only isolated explicit QUIC lab instances support a rebind", 400)
		return
	}
	b := f.active.Load()
	if b == nil {
		http.Error(w, "test backend unavailable", 503)
		return
	}
	// No production instance is referenced and no network/firewall is changed.
	// This closes current sessions, not the peer's trusted identity metadata.
	b.NetworkChanged(true, true)
	writeJSON(w, map[string]any{"rebind_notified": true, "scope": "isolated test carrier only; next packet authenticates a fresh connection"})
}
