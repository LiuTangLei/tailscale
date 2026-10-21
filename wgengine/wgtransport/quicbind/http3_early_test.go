// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Admit only the first ClientHello datagram. The server cannot receive client
// Finished, so a normal post-handshake listener cannot send HTTP/3 SETTINGS.
type holdClientFinished struct {
	net.PacketConn
	writes atomic.Int64
}

func (c *holdClientFinished) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.writes.Add(1) > 1 {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

func TestHTTP3SettingsBeforeClientFinished(t *testing.T) {
	pair := newTestPair(t, "http3-udp")
	pair.open(t)
	client, server := pair.backends[0], pair.backends[1]
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	blocked := &holdClientFinished{PacketConn: pc}
	transport := &quic.Transport{Conn: blocked}
	defer transport.Close()
	config := client.tlsConfig(&server.factory.local)
	// Keep ClientHello in one Initial; this test isolates listener timing.
	config.CurvePreferences = []tls.CurveID{tls.X25519}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	remote := client.factory.peers[server.factory.local].address
	q, err := transport.Dial(ctx, remote, config, client.quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer q.CloseWithError(0, "test complete")
	h3 := (&http3.Transport{EnableDatagrams: true}).NewClientConn(q)
	select {
	case <-h3.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("server waited for client Finished before sending SETTINGS")
	}
	if !h3.Settings().EnableDatagrams || !h3.Settings().EnableExtendedConnect {
		t.Fatal("early SETTINGS lost tunnel capabilities")
	}
	if server.counters.Connections.Load() != 0 || server.counters.HTTP3Tunnels.Load() != 0 || server.counters.ReceivedPackets.Load() != 0 {
		t.Fatal("early SETTINGS authorized a private tunnel")
	}
	if q.ConnectionState().Used0RTT {
		t.Fatal("client early data was enabled")
	}
}
