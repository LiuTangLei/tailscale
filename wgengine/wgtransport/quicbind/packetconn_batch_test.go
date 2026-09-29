// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bytes"
	"errors"
	"github.com/LiuTangLei/wireguard-go/conn"
	"net"
	"tailscale.com/wgengine/wgtransport"
	"testing"
	"time"
)

type recordingBatchBind struct {
	conn.Bind
	batch    int
	packets  [][]byte
	calls    int
	endpoint conn.Endpoint
	fail     error
}

func (b *recordingBatchBind) BatchSize() int { return b.batch }
func (b *recordingBatchBind) Send(packets [][]byte, ep conn.Endpoint, offset int) error {
	if len(packets) > b.batch || offset != 8 {
		return errors.New("host batch/headroom invariant")
	}
	b.calls++
	b.endpoint = ep
	for _, p := range packets {
		for i := 0; i < offset; i++ {
			p[i] = 0x78
		} // emulate relay prepending its header
		b.packets = append(b.packets, bytes.Clone(p[offset:]))
	}
	return b.fail
}
func TestPacketConnBatchHeadroomOwnershipAndBounds(t *testing.T) {
	host := &recordingBatchBind{batch: 2}
	g := &generation{b: &Backend{host: wgtransport.Host{Bind: host}}}
	c := newBindPacketConn(g)
	ep := &endpoint{}
	addr := &bindAddr{ep: ep}
	input := [][]byte{{1, 2}, {3, 4, 5}, {6}, {7, 8, 9}}
	originals := make([][]byte, len(input))
	for i, p := range input {
		originals[i] = bytes.Clone(p)
	}
	if err := c.WritePacketBatch(input, addr); err != nil {
		t.Fatal(err)
	}
	if host.calls != 2 || host.endpoint != ep {
		t.Fatal("host batch size or original endpoint lost")
	}
	for i, p := range input {
		if !bytes.Equal(p, originals[i]) || !bytes.Equal(host.packets[i], p) {
			t.Fatal("caller bytes modified or datagram boundaries lost")
		}
	}
	before := host.calls
	if err := c.WritePacketBatch([][]byte{{1}, make([]byte, 2041)}, addr); err == nil || host.calls != before {
		t.Fatal("invalid batch partially written")
	}
	if err := c.WritePacketBatch(input, &net.UDPAddr{}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatal(err)
	}
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if err := c.WritePacketBatch(input, addr); err == nil {
		t.Fatal("ignored deadline")
	}
	c.SetWriteDeadline(time.Time{})
	c.Close()
	if err := c.WritePacketBatch(input, addr); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
func TestPacketConnBatchDoesNotRetryPartialHostError(t *testing.T) {
	failure := errors.New("host partial failure")
	host := &recordingBatchBind{batch: 8, fail: failure}
	c := newBindPacketConn(&generation{b: &Backend{host: wgtransport.Host{Bind: host}}})
	if err := c.WritePacketBatch([][]byte{{1}, {2}}, &bindAddr{ep: &endpoint{}}); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if host.calls != 1 {
		t.Fatal("potential partial send retried")
	}
}

func TestPacketConnExpandedBatch(t *testing.T) {
	host := &recordingBatchBind{batch: 7}
	c := newBindPacketConn(&generation{b: &Backend{host: wgtransport.Host{Bind: host}}})
	defer c.Close()
	input := make([][]byte, 32)
	for i := range input {
		input[i] = bytes.Repeat([]byte{byte(i)}, 1200-i)
	}
	addr := &bindAddr{ep: &endpoint{}}
	if c.MaxPacketBatchSize() != 32 {
		t.Fatal("wrong negotiated limit")
	}
	if err := c.WritePacketBatch(input, addr); err != nil {
		t.Fatal(err)
	}
	if host.calls != 5 || len(host.packets) != 32 {
		t.Fatal("host capacity or packet count changed")
	}
	for i, p := range host.packets {
		if !bytes.Equal(p, input[i]) {
			t.Fatal("packet boundary, order or borrowed bytes changed")
		}
	}
	if err := c.WritePacketBatch(append(input, []byte{1}), addr); err == nil || host.calls != 5 {
		t.Fatal("oversized group was partially sent")
	}
}
