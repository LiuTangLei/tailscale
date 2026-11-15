package magicsock

import (
	"bytes"
	"context"
	"net/netip"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/types/key"
	"tailscale.com/util/clientmetric"
)

var metricSendDERPQueueWait = clientmetric.NewCounter("magicsock_send_derp_queue_wait")
var metricSendDERPQueueWaitNS = clientmetric.NewCounter("magicsock_send_derp_queue_wait_ns")

// SendWithContext is an opt-in carrier operation. Native WireGuard still uses
// Send: its callers may hold internal locks and must never wait on DERP. A QUIC
// sender owns an independent, cancellable send queue and can propagate pressure
// instead of evicting packets that QUIC already considers sent.
func (c *Conn) SendWithContext(ctx context.Context, buffs [][]byte, ep conn.Endpoint, offset int) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	endpoint, ok := ep.(*endpoint)
	if !ok {
		return c.Send(buffs, ep, offset)
	}
	n := int64(len(buffs))
	defer func() {
		if err != nil {
			c.metrics.outboundPacketsDroppedErrors.Add(n)
		}
	}()
	metricSendData.Add(n)
	if c.networkDown() {
		metricSendDataNetworkDown.Add(n)
		return errNetworkDown
	}
	return endpoint.sendWithContext(ctx, buffs, offset)
}

func (c *Conn) sendDERPWithContext(ctx context.Context, addr netip.AddrPort, peer key.NodePublic, packet []byte) (bool, error) {
	ch, writerDone := c.derpWriteChanForRegionWithDone(int(addr.Port()), peer)
	if ch == nil {
		metricSendDERPErrorChan.Add(1)
		return false, errNoUDPOrDERP
	}
	request := derpWriteRequest{addr, peer, bytes.Clone(packet), false}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	select {
	case ch <- request:
		metricSendDERPQueued.Add(1)
		return true, nil
	default:
	}
	metricSendDERPQueueWait.Add(1)
	start := time.Now()
	defer func() { metricSendDERPQueueWaitNS.Add(int64(time.Since(start))) }()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-c.donec:
		return false, errConnClosed
	case <-writerDone:
		return false, errConnClosed
	case ch <- request:
		metricSendDERPQueued.Add(1)
		return true, nil
	}
}
