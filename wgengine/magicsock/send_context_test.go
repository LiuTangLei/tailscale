package magicsock

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func relayQueueFixture(t *testing.T) (*Conn, chan derpWriteRequest, context.CancelFunc) {
	t.Helper()
	c := newConn(t.Logf)
	c.privateKey = key.NewNode()
	c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())
	c.donec = c.connCtx.Done()
	t.Cleanup(c.connCtxCancel)
	c.derpMap = &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1}}}
	writer, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan derpWriteRequest, derpWriteQueueDepth)
	now := time.Now()
	c.activeDerp = map[int]activeDerp{1: {writeCh: ch, done: writer.Done(), lastWrite: &now}}
	for range cap(ch) {
		ch <- derpWriteRequest{}
	}
	return c, ch, cancel
}

func TestDERPContextWaitPreservesQueuedPackets(t *testing.T) {
	c, ch, _ := relayQueueFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	payload := []byte("owned after queue admission")
	done := make(chan error, 1)
	go func() {
		ok, err := c.sendDERPWithContext(ctx, netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1), key.NodePublic{}, payload)
		if !ok && err == nil {
			err = errors.New("not admitted")
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("full queue did not backpressure: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if len(ch) != cap(ch) {
		t.Fatal("old packets were evicted")
	}
	<-ch
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	clear(payload)
	for range cap(ch) - 1 {
		<-ch
	}
	request := <-ch
	if !bytes.Equal(request.b, []byte("owned after queue admission")) {
		t.Fatal("queued packet did not own its bytes")
	}
}

func TestDERPContextWaitCancellation(t *testing.T) {
	for _, mode := range []string{"caller", "writer-retired", "connection-closed"} {
		t.Run(mode, func(t *testing.T) {
			c, ch, retire := relayQueueFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := c.sendDERPWithContext(ctx, netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1), key.NodePublic{}, []byte{42})
				done <- err
			}()
			select {
			case err := <-done:
				t.Fatalf("unexpected completion: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			switch mode {
			case "caller":
				cancel()
			case "writer-retired":
				retire()
			case "connection-closed":
				c.connCtxCancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancellation reported success")
				}
			case <-time.After(time.Second):
				t.Fatal("canceled queue wait hung")
			}
			if len(ch) != cap(ch) {
				t.Fatal("cancellation evicted another packet")
			}
		})
	}
}

func TestNativeDERPSendStillNonblocking(t *testing.T) {
	c, ch, _ := relayQueueFixture(t)
	done := make(chan bool, 1)
	go func() {
		ok, _ := c.sendAddr(netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 1), key.NodePublic{}, []byte{42}, false, false)
		done <- ok
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("native admission failed")
		}
	case <-time.After(time.Second):
		t.Fatal("native send started waiting")
	}
	if len(ch) != cap(ch) {
		t.Fatal("native queue capacity changed")
	}
}
