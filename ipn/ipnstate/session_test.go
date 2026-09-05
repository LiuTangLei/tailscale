// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package ipnstate

import (
	"tailscale.com/types/key"
	"testing"
	"time"
)

func TestNativeSessionStatusDoesNotFabricateWireGuard(t *testing.T) {
	k := key.NewNode().Public()
	var sb StatusBuilder
	now := time.Now()
	sb.AddPeer(k, &PeerStatus{LastHandshake: now, SessionProtocol: "wireguard"})
	sb.AddPeer(k, &PeerStatus{SessionProtocol: "quic-ip", SessionState: 2, LastSessionEstablished: now.Add(time.Second)})
	sb.AddPeer(k, &PeerStatus{HostName: "retained", RxBytes: 123})
	got := sb.Status().Peer[k]
	if got == nil || got.SessionProtocol != "quic-ip" || got.SessionState != 2 || got.LastSessionEstablished.IsZero() || !got.LastHandshake.IsZero() || got.HostName != "retained" {
		t.Fatalf("wrong merged session: %+v", got)
	}
	// The no-session transition must clear stale established metadata too.
	var empty StatusBuilder
	empty.AddPeer(k, &PeerStatus{SessionProtocol: "quic-ip", SessionState: 2, LastSessionEstablished: now})
	empty.AddPeer(k, &PeerStatus{SessionProtocol: "quic-ip", SessionState: 0})
	if got := empty.Status().Peer[k]; got.SessionState != 0 || !got.LastSessionEstablished.IsZero() {
		t.Fatalf("stale native session: %+v", got)
	}
}
