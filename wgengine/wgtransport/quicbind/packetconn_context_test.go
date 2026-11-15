package quicbind

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/wgengine/wgtransport"
)

type contextHostBind struct {
	conn.Bind
	entered chan [][]byte
	release chan struct{}
}

func (*contextHostBind) BatchSize() int { return 8 }
func (*contextHostBind) Send([][]byte, conn.Endpoint, int) error {
	return errors.New("bypassed contextual host send")
}
func (h *contextHostBind) SendWithContext(ctx context.Context, p [][]byte, _ conn.Endpoint, offset int) error {
	if offset != 8 {
		return errors.New("lost headroom")
	}
	h.entered <- p
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-h.release:
		return nil
	}
}
func TestPacketConnContextBatchOwnershipAndCancel(t *testing.T) {
	for _, count := range []int{1, 8} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			h := &contextHostBind{entered: make(chan [][]byte, 1), release: make(chan struct{})}
			c := &contextBindPacketConn{newBindPacketConn(&generation{b: &Backend{host: wgtransport.Host{Bind: h}}})}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			packets := make([][]byte, count)
			for i := range packets {
				packets[i] = bytes.Repeat([]byte{byte(i + 1)}, 128)
			}
			done := make(chan error, 1)
			go func() { done <- c.WritePacketBatchContext(ctx, packets, &bindAddr{ep: &endpoint{}}) }()
			var held [][]byte
			select {
			case held = <-h.entered:
			case <-time.After(time.Second):
				t.Fatal("contextual writer not used")
			}
			for i, p := range held {
				if !bytes.Equal(p[8:], packets[i]) {
					t.Fatal("borrowed bytes modified before return")
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not unblock adapter")
			}
		})
	}
}

func TestPacketConnContextHonorsWriteDeadline(t *testing.T) {
	h := &contextHostBind{entered: make(chan [][]byte, 1), release: make(chan struct{})}
	c := &contextBindPacketConn{newBindPacketConn(&generation{b: &Backend{host: wgtransport.Host{Bind: h}}})}
	c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	done := make(chan error, 1)
	go func() { done <- c.WritePacketBatchContext(t.Context(), [][]byte{{1}}, &bindAddr{ep: &endpoint{}}) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked relay ignored write deadline")
	}
}

func TestPacketConnContextCapabilityMatchesHost(t *testing.T) {
	type contextWriter interface {
		WritePacketBatchContext(context.Context, [][]byte, net.Addr) error
	}
	plain := newBindPacketConn(&generation{b: &Backend{host: wgtransport.Host{Bind: &recordingBatchBind{batch: 8}}}})
	if _, ok := plain.packetConn().(contextWriter); ok {
		t.Fatal("uncancellable host advertised cancellable queue writes")
	}
	host := &contextHostBind{}
	cancellable := newBindPacketConn(&generation{b: &Backend{host: wgtransport.Host{Bind: host}}})
	if _, ok := cancellable.packetConn().(contextWriter); !ok {
		t.Fatal("cancellable host capability lost")
	}
}
