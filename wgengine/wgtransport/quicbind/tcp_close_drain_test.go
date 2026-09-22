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

func newCloseDrainPair(t *testing.T, handler func(net.Conn)) (*tcpStreamConn, <-chan *tcpStreamConn) {
	t.Helper()
	accepted := make(chan *tcpStreamConn, 1)
	index := 0
	pair := newTestPair(t, "http3-magicsock", func(c *Config) {
		c.AutoTrust, c.TCPStreams, c.BBRv3 = true, true, true
		c.Server, c.Peers = index == 1, nil
		c.AuthenticationSecret = [32]byte{6, 2, 4}
		c.TCPNodeAddress = tcpTestAddress
		if index == 1 {
			c.TCPHandler = func(_ [32]byte, _ netip.AddrPort) func(net.Conn) {
				return func(conn net.Conn) {
					accepted <- conn.(*tcpStreamConn)
					handler(conn)
				}
			}
		}
		index++
	})
	pair.open(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	key := pair.keys[1].Public().Raw32()
	conn, err := pair.backends[0].DialTCPStream(ctx, key, netip.AddrPortFrom(tcpTestAddress(key), 8080))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*tcpStreamConn), accepted
}

func TestHTTP3CloseAllowsPeerFinalBytesAndFIN(t *testing.T) {
	response := bytes.Repeat([]byte("complete response\n"), 8192)
	c, accepted := newCloseDrainPair(t, func(conn net.Conn) {
		defer conn.Close()
		request := make([]byte, 4)
		if _, err := io.ReadFull(conn, request); err != nil {
			return
		}
		_, _ = conn.Write(response)
		// Close after the logical SSH request, without waiting for the
		// client's final protocol disconnect or its transport FIN.
	})
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("exec")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("response truncated: bytes=%d, err=%v", len(got), err)
	}
	server := <-accepted
	select {
	case <-server.Done():
	case <-time.After(time.Second):
		t.Fatal("server did not close its application connection")
	}
	// Final client bytes deliberately follow the response EOF. The old
	// immediate CancelRead reset the client's send stream here.
	if _, err := c.Write(bytes.Repeat([]byte("disconnect"), 1024)); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	select {
	case <-c.drained:
		if c.drainErr != nil {
			t.Fatalf("final bytes/FIN were reset: %v", c.drainErr)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("write acknowledgement did not finish")
	}
	select {
	case <-server.readerDone:
	case <-time.After(time.Second):
		t.Fatal("receive pump did not finish after peer FIN")
	}
}

func TestHTTP3CloseReadStillAbortsAndReportsDrainFailure(t *testing.T) {
	ready := make(chan struct{})
	c, accepted := newCloseDrainPair(t, func(conn net.Conn) {
		<-ready
		_ = conn.(*tcpStreamConn).CloseRead()
		_, _ = conn.Write([]byte("done"))
		_ = conn.Close()
	})
	server := <-accepted
	close(ready)
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	_, _ = io.ReadAll(c)
	_, _ = c.Write(bytes.Repeat([]byte("must not report delivered"), 1024))
	_ = c.Close()
	select {
	case <-c.drained:
		if c.drainErr == nil {
			t.Fatal("explicit peer abort was reported as acknowledged delivery")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("explicit abort failed to unblock write acknowledgement")
	}
	select {
	case <-server.readerDone:
	case <-time.After(time.Second):
		t.Fatal("CloseRead did not immediately release receive pump")
	}
}

func TestHTTP3CloseDrainDeadlineBoundsSilentPeer(t *testing.T) {
	c, accepted := newCloseDrainPair(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("done"))
		_ = conn.Close()
	})
	_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	// Do not send FIN. The abandoned receive side must still terminate.
	select {
	case <-server.readerDone:
	case <-time.After(closedReadGrace + 2*time.Second):
		t.Fatal("silent peer retained a closed receive pump")
	}
}
