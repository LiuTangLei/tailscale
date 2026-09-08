// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

import (
	"bytes"
	"encoding/hex"
	"slices"
)

// Snapshot reports only this running backend; a shared factory owns no engine.
func (b *Backend) Snapshot() map[string]any {
	return b.factory.snapshotBackend(b)
}

func (f *Factory) snapshotBackend(b *Backend) map[string]any {
	out := map[string]any{"io": f.cfg.IO, "alpn": f.protocol(), "quic": true, "payload": f.cfg.Payload, "wireguard_encryption": false, "server": f.cfg.Server, "browser_fingerprint": "none", "browser_fingerprint_supported": true}
	out["authentication"] = "pinned-key"
	if f.cfg.AutoTrust {
		out["authentication"] = "node-key"
		out["authentication_protocol"] = "Noise_IK_25519_ChaChaPoly_BLAKE2s/v2"
	}
	out["manual_identity_required"] = !f.cfg.AutoTrust
	if b == nil {
		return out
	}
	out["session_refresh_seconds"] = b.timing.refresh.Seconds()
	out["session_max_age_seconds"] = b.timing.expire.Seconds()
	if b.host.PacketStats != nil {
		out["ip_data_plane"] = b.host.PacketStats()
	}
	c := &b.counters
	out["http3"] = f.cfg.HTTP3
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
		slices.SortFunc(ps, func(a, b *peer) int { return bytes.Compare(a.cfg.key[:], b.cfg.key[:]) })
		active := 0
		profiles := map[string]bool{}
		var details []map[string]any
		queuedTotal, queuedBytesTotal := 0, 0
		var dropsTotal uint64
		for _, p := range ps {
			hint := b.peerServerHint(p.cfg.key)
			detail := map[string]any{"peer": hex.EncodeToString(p.cfg.key[:]), "remote_server_known": hint != serverUnknown, "remote_server": hint == serverYes, "browser_eligible_next_outbound": b.browserProfileEligible(p.cfg.key, true), "browser_fingerprint": "none"}
			details = append(details, detail)
			p.mu.Lock()
			s := p.session
			p.mu.Unlock()
			if s != nil && s.q.Context().Err() == nil {
				active++
				detail["connection_stats"] = s.q.ConnectionStats()
				detail["local_tls_role"] = "server"
				if s.outgoing {
					detail["local_tls_role"] = "client"
				}
				// Preserve legacy scalar diagnostics only for an unambiguous
				// single connection; never select a random peer from a map.
				if active == 1 {
					out["connection_stats"] = detail["connection_stats"]
				}
				if stats, ok := any(s.q).(interface{ DatagramReceiveQueueStats() (int, int, uint64) }); ok {
					queued, queuedBytes, drops := stats.DatagramReceiveQueueStats()
					detail["quic_receive_queue_packets"], detail["quic_receive_queue_bytes"], detail["quic_receive_queue_drops"] = queued, queuedBytes, drops
					queuedTotal += queued
					queuedBytesTotal += queuedBytes
					dropsTotal += drops
				}
				state := s.q.ConnectionState()
				profile := "none"
				if state.ClientHelloProfile != "" {
					profile = state.ClientHelloProfile
				}
				detail["browser_fingerprint"] = profile
				profiles[profile] = true
				detail["tls_version"], detail["tls_cipher_suite"] = state.TLS.Version, state.TLS.CipherSuite
				detail["datagrams"] = state.SupportsDatagrams.Local && state.SupportsDatagrams.Remote
				if active == 1 {
					out["browser_fingerprint"] = profile
					out["tls_version"], out["tls_cipher_suite"], out["datagrams"] = detail["tls_version"], detail["tls_cipher_suite"], detail["datagrams"]
				}
			}
		}
		if len(profiles) > 1 {
			out["browser_fingerprint"] = "mixed"
		} else {
			for profile := range profiles {
				out["browser_fingerprint"] = profile
			}
		}
		out["active_connections"] = active
		out["peers"] = details
		out["quic_receive_queue_packets"], out["quic_receive_queue_bytes"], out["quic_receive_queue_drops"] = queuedTotal, queuedBytesTotal, dropsTotal
		if active > 1 {
			for _, k := range []string{"connection_stats", "tls_version", "tls_cipher_suite", "datagrams"} {
				delete(out, k)
			}
		}
	}
	return out
}
