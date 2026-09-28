package quicbind

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestHTTP3CloseDrainByteBudgetStopsContinuingPeer(t *testing.T) {
	c, accepted := newCloseDrainPair(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("done"))
		_ = conn.Close()
	})
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	_, writeErr := c.Write(bytes.Repeat([]byte{0x5a}, 2*closedReadLimit))
	_ = c.Close()
	select {
	case <-server.readerDone:
	case <-time.After(closedReadGrace + time.Second):
		t.Fatal("continuing sender retained a closed receive pump")
	}
	select {
	case <-c.drained:
		if writeErr == nil && c.drainErr == nil {
			t.Fatal("data beyond the close budget was reported delivered")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("budget reset did not terminate the sender")
	}
}
