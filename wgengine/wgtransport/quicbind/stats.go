// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"sort"
)

// Snapshot contains counters and public peer identifiers, never private keys,
// certificates or packet contents. A factory is normally
// used for one engine; with multiple engines this reports the last created one.
func (f *Factory) Snapshot() map[string]any {
	return f.snapshotBackend(f.last.Load())
}

// Snapshot reports only this running backend. Factory.Snapshot remains a
// compatibility helper for callers that deliberately use one factory/engine.
func (b *Backend) Snapshot() map[string]any {
	return b.factory.snapshotBackend(b)
}

func (f *Factory) snapshotBackend(b *Backend) map[string]any {
	out := map[string]any{"io": f.cfg.IO, "alpn": f.protocol(), "quic": true, "payload": f.cfg.Payload, "wireguard_encryption": f.cfg.Payload != "ip"}
	if b == nil {
		return out
	}
	if b.host.PacketStats != nil {
		out["ip_data_plane"] = b.host.PacketStats()
	}
	c := &b.counters
	out["http3"] = f.cfg.HTTP3
	out["connection_id_length"] = 8
	out["browser_fingerprint"] = "none"
	out["dial_attempts"] = c.DialAttempts.Load()
	out["role_rejections"] = c.RoleRejections.Load()
	out["http3_receive_queue_capacity"] = http3ReceiveQueueCapacity
	out["quic_receive_queue_capacity"] = quicReceiveQueueCapacity
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
		sort.Slice(ps, func(i, j int) bool { return bytes.Compare(ps[i].cfg.key[:], ps[j].cfg.key[:]) < 0 })
		out["listener_enabled"] = g.listener != nil
		active, clients, servers := 0, 0, 0
		var peerStats []map[string]any
		var totalQueued, totalQueuedBytes int
		var totalDrops uint64
		for _, p := range ps {
			p.mu.Lock()
			s := p.session
			p.mu.Unlock()
			entry := map[string]any{"peer_public_key": hex.EncodeToString(p.cfg.key[:]), "configured_role": p.cfg.role, "active": false}
			peerStats = append(peerStats, entry)
			if s != nil && s.q.Context().Err() == nil {
				active++
				entry["active"] = true
				entry["connection_stats"] = s.q.ConnectionStats()
				if s.outgoing {
					entry["tls_role"] = "client"
					clients++
				} else {
					entry["tls_role"] = "server"
					servers++
				}
				out["connection_stats"] = entry["connection_stats"]
				if stats, ok := any(s.q).(interface{ DatagramReceiveQueueStats() (int, int, uint64) }); ok {
					queued, queuedBytes, drops := stats.DatagramReceiveQueueStats()
					entry["quic_receive_queue_packets"] = queued
					entry["quic_receive_queue_bytes"] = queuedBytes
					entry["quic_receive_queue_drops"] = drops
					totalQueued += queued
					totalQueuedBytes += queuedBytes
					totalDrops += drops
				}
				state := s.q.ConnectionState()
				out["tls_version"] = state.TLS.Version
				out["tls_cipher_suite"] = state.TLS.CipherSuite
				out["datagrams"] = state.SupportsDatagrams.Local && state.SupportsDatagrams.Remote
			}
		}
		// Single-peer benchmarks retain their old convenience field. Reporting
		// one arbitrary connection as the whole mesh would hide role and speed
		// differences, so multi-peer callers must read peer_connections.
		if active != 1 {
			delete(out, "connection_stats")
			delete(out, "tls_cipher_suite")
		}
		out["active_connections"] = active
		out["client_connections"] = clients
		out["server_connections"] = servers
		out["peer_connections"] = peerStats
		out["quic_receive_queue_packets"] = totalQueued
		out["quic_receive_queue_bytes"] = totalQueuedBytes
		out["quic_receive_queue_drops"] = totalDrops
	}
	return out
}
