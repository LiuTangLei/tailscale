// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package wgengine

import (
	"tailscale.com/net/tsaddr"
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
			fn := e.peerConfigFn.Load()
			if fn == nil {
				continue
			}
			ips, ok := (*fn)(k)
			if !ok {
				continue
			}
			for _, p := range ips {
				if p.IsSingleIP() && tsaddr.IsTailscaleIP(p.Addr()) {
					e.sendTSMPDiscoAdvertisement(p.Addr())
					break
				}
			}
		}
	}
}
