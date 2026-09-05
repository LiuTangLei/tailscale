// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgtransport

import (
	"fmt"

	"github.com/LiuTangLei/wireguard-go/conn"
)

// Endpoint wraps an underlying endpoint while retaining WireGuard's optional
// handshake/peer identity callbacks. Providers may embed it to carry session
// metadata. Construct it using WrapEndpoint; do not replace the base endpoint
// with an IP parsed from DstToString (magicsock uses node keys there).
type Endpoint struct{ conn.Endpoint }

func WrapEndpoint(ep conn.Endpoint) (*Endpoint, error) {
	if isNil(ep) {
		return nil, conn.ErrWrongEndpointType
	}
	return &Endpoint{Endpoint: ep}, nil
}

// UnderlyingEndpoint identifies the host endpoint for the final network send.
func (e *Endpoint) UnderlyingEndpoint() conn.Endpoint { return e.Endpoint }

func (e *Endpoint) InitiationMessagePublicKey(pk [32]byte) {
	if p, ok := e.Endpoint.(conn.InitiationAwareEndpoint); ok {
		p.InitiationMessagePublicKey(pk)
	}
}

func (e *Endpoint) FromPeer(pk [32]byte) {
	if p, ok := e.Endpoint.(conn.PeerAwareEndpoint); ok {
		p.FromPeer(pk)
	}
}

// UnwrapEndpoint removes carrier metadata before magicsock's concrete endpoint
// dispatch. Bounded traversal rejects broken/cyclic wrappers instead of hanging.
// An unrecognized final host endpoint is rejected by the host, never dropped
// with a nil send error.
func UnwrapEndpoint(ep conn.Endpoint) (conn.Endpoint, error) {
	for range 16 {
		if isNil(ep) {
			return nil, conn.ErrWrongEndpointType
		}
		w, ok := ep.(interface{ UnderlyingEndpoint() conn.Endpoint })
		if !ok {
			return ep, nil
		}
		ep = w.UnderlyingEndpoint()
	}
	return nil, fmt.Errorf("%w: excessive or cyclic transport endpoint wrapping", conn.ErrWrongEndpointType)
}

var (
	_ conn.Endpoint                = (*Endpoint)(nil)
	_ conn.InitiationAwareEndpoint = (*Endpoint)(nil)
	_ conn.PeerAwareEndpoint       = (*Endpoint)(nil)
)
