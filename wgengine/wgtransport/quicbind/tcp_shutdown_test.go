// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestHTTP3TCPShutdownUnblocksFullReadQueue(t *testing.T) {
	index := 0
	pair := newTestPair(t, "http3-magicsock", func(c *Config) {
		c.AutoTrust, c.TCPStreams, c.BBRv3 = true, true, true
		c.Peers = nil
		c.Server = index == 1
		c.TCPNodeAddress = tcpTestAddress
		c.AuthenticationSecret = [32]byte{3, 8, 4}
		if index == 1 {
			c.TCPHandler = func(_ [32]byte, _ netip.AddrPort) func(net.Conn) {
				return func(c net.Conn) {
					defer c.Close()
					_, _ = io.Copy(c, c)
				}
			}
		}
		index++
	})
	pair.open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	remote := pair.keys[1].Public().Raw32()
	conn, err := pair.backends[0].DialTCPStream(ctx, remote, netip.AddrPortFrom(tcpTestAddress(remote), 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := conn.(*tcpStreamConn)
	if _, err := conn.Write(bytes.Repeat([]byte{0x43}, 256<<10)); err != nil {
		t.Fatal(err)
	}
	for len(c.readQ) != cap(c.readQ) {
		select {
		case <-ctx.Done():
			t.Fatal("read queue did not fill")
		case <-time.After(time.Millisecond):
		}
	}
	if err := pair.backends[1].Close(); err != nil {
		t.Fatal(err)
	}
	// No application Read/Close is needed to release a pump blocked behind
	// a full queue after its underlying authenticated connection disappears.
	select {
	case <-c.readerDone:
	case <-ctx.Done():
		t.Fatal("read pump leaked after peer shutdown")
	}
	select {
	case <-c.drained:
	case <-ctx.Done():
		t.Fatal("write drain leaked after peer shutdown")
	}
}
