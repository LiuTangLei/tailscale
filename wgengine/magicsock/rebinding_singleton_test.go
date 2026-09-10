// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/ipv6"
	"tailscale.com/net/batching"
	"tailscale.com/net/packet"
	"tailscale.com/types/nettype"
)

type singletonTestConn struct {
	nettype.PacketConn
	singles, batches int
	payload          []byte
	destination      netip.AddrPort
	err              error
	beforeWrite      func()
}

var _ batching.Conn = (*singletonTestConn)(nil)

func (c *singletonTestConn) ReadBatch([]ipv6.Message, int) (int, error) {
	return 0, errors.New("unused")
}
func (c *singletonTestConn) WriteBatchTo(_ [][]byte, a netip.AddrPort, _ packet.GeneveHeader, _ int) error {
	c.batches++
	c.destination = a
	return c.err
}
func (c *singletonTestConn) WriteToUDPAddrPort(p []byte, a netip.AddrPort) (int, error) {
	c.singles++
	c.payload = bytes.Clone(p)
	c.destination = a
	if c.beforeWrite != nil {
		c.beforeWrite()
	}
	if c.err != nil {
		return 0, c.err
	}
	return len(p), nil
}
func installSingletonTestConn(c *RebindingUDPConn, p nettype.PacketConn) {
	c.mu.Lock()
	c.pconn = p
	c.pconnAtomic.Store(&p)
	c.mu.Unlock()
}
func TestRebindingSingletonAvoidsBatchSetup(t *testing.T) {
	for _, ip := range []string{"192.0.2.1:12345", "[2001:db8::1]:12345"} {
		for _, encapsulated := range []bool{false, true} {
			c := new(RebindingUDPConn)
			socket := new(singletonTestConn)
			installSingletonTestConn(c, socket)
			addr := epAddr{ap: netip.MustParseAddrPort(ip)}
			if encapsulated {
				addr.vni.Set(42)
			}
			payload := []byte{0x40, 1, 2, 3, 4, 5}
			buf := append(make([]byte, 8), payload...)
			if err := c.WriteWireGuardBatchTo([][]byte{buf}, addr, 8); err != nil {
				t.Fatal(err)
			}
			if socket.singles != 1 || socket.batches != 0 || socket.destination != addr.ap {
				t.Fatal("singleton used batch machinery or wrong address")
			}
			if encapsulated {
				var header packet.GeneveHeader
				if err := header.Decode(socket.payload); err != nil || header.VNI.Get() != 42 || header.Protocol != packet.GeneveProtocolWireGuard {
					t.Fatal("Geneve changed", err)
				}
				if !bytes.Equal(socket.payload[8:], payload) {
					t.Fatal("encapsulated payload changed")
				}
			} else if !bytes.Equal(socket.payload, payload) {
				t.Fatal("headroom was sent on direct path")
			}
			if err := c.WriteWireGuardBatchTo([][]byte{buf, buf}, addr, 8); err != nil {
				t.Fatal(err)
			}
			if socket.batches != 1 {
				t.Fatal("multi-packet send lost batching")
			}
			if c.WriteWireGuardBatchTo([][]byte{buf}, addr, 0) == nil {
				t.Fatal("invalid offset accepted")
			}
		}
	}
}
func TestRebindingSingletonRetryAndErrors(t *testing.T) {
	c := new(RebindingUDPConn)
	next := new(singletonTestConn)
	old := &singletonTestConn{err: net.ErrClosed}
	old.beforeWrite = func() { installSingletonTestConn(c, next) }
	installSingletonTestConn(c, old)
	addr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:12345")}
	if err := c.WriteWireGuardBatchTo([][]byte{append(make([]byte, 8), 1, 2, 3)}, addr, 8); err != nil {
		t.Fatal(err)
	}
	if old.singles != 1 || next.singles != 1 || !bytes.Equal(next.payload, []byte{1, 2, 3}) {
		t.Fatal("rebind lost/duplicated payload")
	}
	next.err = net.ErrClosed
	if err := c.WriteWireGuardBatchTo([][]byte{make([]byte, 9)}, addr, 8); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write error hidden: %v", err)
	}
}
