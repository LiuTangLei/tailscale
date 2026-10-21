// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/packet"
)

// A reliable stream that cannot deliver more bytes must not impose ordered
// delivery or a stream-flow-control wait on UDP carried by CONNECT-IP.
func TestUDPDeliveryWhileReliableStreamIsBlocked(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	release := make(chan struct{})
	index := 0
	pair := newTestPair(t, "http3-magicsock", func(c *Config) {
		c.AutoTrust, c.TCPStreams = true, true
		c.Peers, c.Server = nil, index == 1
		c.TCPNodeAddress = tcpTestAddress
		if index == 1 {
			c.TCPHandler = func(_ [32]byte, _ netip.AddrPort) func(net.Conn) {
				return func(c net.Conn) { defer c.Close(); accepted <- c; <-release }
			}
		}
		index++
	})
	t.Cleanup(func() { close(release) })
	fns := pair.open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	remote := pair.keys[1].Public().Raw32()
	client, err := pair.backends[0].DialTCPStream(ctx, remote, netip.AddrPortFrom(tcpTestAddress(remote), 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server *tcpStreamConn
	select {
	case conn := <-accepted:
		server = conn.(*tcpStreamConn)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write(make([]byte, 8<<20))
		writeDone <- err
	}()
	// The server deliberately does not Read. Its bounded read queue fills and
	// its QUIC stream eventually exhausts receive credit.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for len(server.readQ) < cap(server.readQ) || len(client.(*tcpStreamConn).writeQ) < cap(client.(*tcpStreamConn).writeQ) {
		select {
		case err := <-writeDone:
			t.Fatalf("stream did not remain backpressured: %v", err)
		case <-ctx.Done():
			t.Fatal("reliable stream did not fill bounded queues")
		case <-ticker.C:
		}
	}
	ep, err := pair.backends[0].Bind().ParseEndpoint(hex.EncodeToString(remote[:]))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		h := &packet.UDP4Header{IP4Header: packet.IP4Header{Src: netip.MustParseAddr("10.88.0.1"), Dst: netip.MustParseAddr("10.88.0.2")}, SrcPort: 1234, DstPort: 5678}
		data := packet.Generate(h, []byte{byte(i), 7, 8, 9})
		if err := pair.backends[0].Bind().Send([][]byte{data}, ep, 0); err != nil {
			t.Fatal(err)
		}
		if got := readOne(t, fns[1]); !bytes.Equal(got, data) {
			t.Fatal("UDP packet changed, duplicated or reordered behind the blocked stream")
		}
	}
	select {
	case err := <-writeDone:
		t.Fatalf("test no longer exercised a blocked reliable stream: %v", err)
	default:
	}
	_ = client.Close()
	select {
	case <-writeDone:
	case <-ctx.Done():
		t.Fatal("closing the stream did not release its writer")
	}
}
