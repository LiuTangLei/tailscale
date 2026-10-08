// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package wgengine

import (
	"tailscale.com/wgengine/wgtransport"
)

// Called by the carrier with lifecycle serialization held. Keep it bounded;
// host routing and TUN injection run on a separate, single worker.
func (e *userspaceEngine) carrierSessionChanged(k [32]byte, s wgtransport.SessionState) {
	e.packet.CarrierSessionChanged(k, s)
	if s == wgtransport.SessionEstablished {
		select {
		case e.sessionDisco <- keyFromRaw(k):
		default:
		}
	}
}
func (e *userspaceEngine) sendSessionDiscoNotifications() {
	for {
		select {
		case <-e.waitCh:
			return
		case k := <-e.sessionDisco:
			e.mu.Lock()
			closing := e.closing
			e.mu.Unlock()
			if closing || !e.peerCurrentlyAllowed(k) {
				continue
			}
			if payload := e.magicConn.PriorityMessageForPeer(k); len(payload) > 0 {
				if err := e.tundev.InjectOutbound(payload); err != nil {
					e.logf("QUIC session discovery advertisement: %v", err)
				}
			}
		}
	}
}
