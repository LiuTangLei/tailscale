// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

// Snapshot contains counters, not keys or packet contents. A factory is normally
// used for one engine; with multiple engines this reports the last created one.
func (f *Factory) Snapshot() map[string]any {
	out := map[string]any{"io": f.cfg.IO, "alpn": f.protocol(), "quic": true, "payload": f.cfg.Payload, "wireguard_encryption": f.cfg.Payload != "ip"}
	b := f.last.Load()
	if b == nil {
		return out
	}
	if b.host.PacketStats != nil {
		out["ip_data_plane"] = b.host.PacketStats()
	}
	c := &b.counters
	out["http3"] = f.cfg.HTTP3
	out["http3_receive_queue_capacity"] = http3ReceiveQueueCapacity
	out["http3_requests"] = c.HTTP3Requests.Load()
	out["http3_public_requests"] = c.HTTP3PublicRequests.Load()
	out["http3_public_pages"] = c.HTTP3PublicPages.Load()
	out["http3_tunnels"] = c.HTTP3Tunnels.Load()
	out["http3_rejected"] = c.HTTP3Rejected.Load()
	out["http3_datagrams"] = c.HTTP3Datagrams.Load()
	out["sent_packets"] = c.SentPackets.Load()
	out["received_packets"] = c.ReceivedPackets.Load()
	out["send_drops"] = c.SendQueueDrops.Load()
	out["send_errors"] = c.SendErrors.Load()
	out["enqueue_waits"] = c.EnqueueWaits.Load()
	out["fast_packets"] = c.FastPackets.Load()
	out["receive_drops"] = c.ReceiveQueueDrops.Load()
	out["fragmented_packets"] = c.FragmentedPackets.Load()
	out["malformed_frames"] = c.MalformedFrames.Load()
	out["connections"] = c.Connections.Load()
	out["handshake_errors"] = c.HandshakeErrors.Load()
	out["raw_drops"] = c.RawPacketsDropped.Load()
	out["raw_bytes_sent"] = c.RawBytesSent.Load()
	out["raw_bytes_received"] = c.RawBytesReceived.Load()
	out["identity_ok"] = b.identityOK.Load()
	if g := b.active.Load(); g != nil {
		out["tx_queued_bytes"] = g.txBytes.Load()
		out["rx_queued_bytes"] = g.rxBytes.Load()
		g.peersMu.Lock()
		ps := make([]*peer, 0, len(g.peers))
		for _, p := range g.peers {
			ps = append(ps, p)
		}
		g.peersMu.Unlock()
		active := 0
		for _, p := range ps {
			p.mu.Lock()
			s := p.session
			p.mu.Unlock()
			if s != nil && s.q.Context().Err() == nil {
				active++
				out["connection_stats"] = s.q.ConnectionStats()
				state := s.q.ConnectionState()
				out["tls_version"] = state.TLS.Version
				out["tls_cipher_suite"] = state.TLS.CipherSuite
				out["datagrams"] = state.SupportsDatagrams.Local && state.SupportsDatagrams.Remote
			}
		}
		out["active_connections"] = active
	}
	return out
}
