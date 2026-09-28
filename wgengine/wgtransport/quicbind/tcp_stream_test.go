package quicbind

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func tcpTestAddress(k [32]byte) netip.Addr {
	var a [16]byte
	a[0],a[1] = 0xfd, 0x12
	copy(a[6:],k[:10])
	return netip.AddrFrom16(a)
}

func TestHTTP3TCPStreamsAuthenticationAndLifetime(t *testing.T) {
	var calls atomic.Int32
	index := 0
	pair := newTestPair(t, "http3-magicsock", func(c *Config) {
		c.AutoTrust, c.HTTP3, c.TCPStreams, c.BBRv3 = true, true, true, true
		c.Server, c.Peers = index == 1, nil
		c.AuthenticationSecret = [32]byte{3,9,1}
		c.TCPNodeAddress = tcpTestAddress
		if index == 1 {
			c.TCPHandler = func(_ [32]byte, dst netip.AddrPort) func(net.Conn) {
				if dst.Port() != 8080 { return nil }
				return func(c net.Conn) { calls.Add(1); defer c.Close(); _,_ = io.Copy(c,c) }
			}
		}
		index++
	})
	pair.open(t)
	ctx,cancel := context.WithTimeout(t.Context(),10*time.Second)
	defer cancel()
	b := pair.backends[0]
	remote := pair.keys[1].Public().Raw32()
	dst := netip.AddrPortFrom(tcpTestAddress(remote),8080)
	p,err:=b.active.Load().peer(remote,nil)
	if err!=nil { t.Fatal(err) }
	// A TLS connection alone, even using known node IDs, is NOT permission
	// to issue arbitrary CONNECTs. No authenticated CONNECT-IP has happened.
	q,err:=p.g.transport.Dial(ctx,&bindAddr{ep:p.ep.Load().Endpoint},b.tlsConfig(&remote),b.quicConfig())
	if err!=nil { t.Fatal(err) }
	hc:=(&http3.Transport{EnableDatagrams:true}).NewClientConn(q)
	select { case <-hc.ReceivedSettings(): case <-ctx.Done(): t.Fatal(ctx.Err()) }
	stream,err:=hc.OpenRequestStream(ctx)
	if err!=nil { t.Fatal(err) }
	req:=&http.Request{Method:http.MethodConnect, Host:dst.String(), URL:&url.URL{Scheme:"https",Host:dst.String()},Header:make(http.Header)}
	if err:=stream.SendRequestHeader(req);err!=nil { t.Fatal(err) }
	response,err:=stream.ReadResponse()
	if err!=nil { t.Fatal(err) }
	if response.StatusCode != 404 || calls.Load()!=0 { t.Fatal("TLS-only peer reached the TCP handler") }
	_ = q.CloseWithError(0,"test complete")

	conn,err:=b.DialTCPStream(ctx,remote,dst)
	if err!=nil { t.Fatal(err) }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8*time.Second))
	payload:=bytes.Repeat([]byte("bounded authenticated HTTP/3 stream\n"),4096)
	writeDone:=make(chan error,1)
	go func(){ _,err:=conn.Write(payload); writeDone<-err }()
	got:=make([]byte,len(payload))
	if _,err:=io.ReadFull(conn,got);err!=nil || !bytes.Equal(payload,got) { t.Fatalf("data integrity: %v",err) }
	if err:=<-writeDone;err!=nil { t.Fatal(err) }
	if calls.Load()!=1 { t.Fatal("wrong handler invocation count") }
	if p.session.q.ConnectionStats().CongestionControl!="bbr-v3" { t.Fatal("stream did not use BBRv3") }
	// Old IP-session TTL and idle cleanup must not cut an open byte stream.
	for _, backend:=range pair.backends {
		backend.active.Load().maintainAt(time.Now().Add(4*time.Minute))
	}
	if _,err:=conn.Write([]byte("alive"));err!=nil { t.Fatal(err) }
	if _,err:=io.ReadFull(conn,got[:5]);err!=nil || string(got[:5])!="alive" { t.Fatalf("open stream expired: %v",err) }
	bad,err:=b.DialTCPStream(ctx,remote,netip.AddrPortFrom(dst.Addr(),8081))
	if bad!=nil || !errors.Is(err,ErrTCPStreamDenied) { t.Fatalf("unserved target admitted: %v",err) }
	if calls.Load()!=1 { t.Fatal("unserved port reached handler") }
	if err:=conn.(*tcpStreamConn).CloseWrite();err!=nil { t.Fatal(err) }
	if _,err:=conn.Read(got);err!=io.EOF { t.Fatalf("missing clean EOF: %v",err) }
	_ = conn.Close()
	if err:=b.DrainTCPStreams(ctx);err!=nil { t.Fatal(err) }
}

func TestHTTP3TCPStreamsRejectWrongApplicationSecret(t *testing.T) {
	index:=0
	var calls atomic.Int32
	pair:=newTestPair(t,"http3-magicsock",func(c *Config){
		c.AutoTrust,c.TCPStreams,c.BBRv3=true,true,true
		c.Peers=nil
		c.Server=index==1
		c.AuthenticationSecret=[32]byte{byte(index+1)}
		c.TCPNodeAddress=tcpTestAddress
		c.TCPHandler=func(_ [32]byte,_ netip.AddrPort)func(net.Conn){ calls.Add(1);return func(c net.Conn){c.Close()} }
		index++
	})
	pair.open(t)
	ctx,cancel:=context.WithTimeout(t.Context(),5*time.Second)
	defer cancel()
	k:=pair.keys[1].Public().Raw32()
	conn,err:=pair.backends[0].DialTCPStream(ctx,k,netip.AddrPortFrom(tcpTestAddress(k),8080))
	if conn!=nil || err==nil || calls.Load()!=0 { t.Fatal("wrong secret created a TCP stream") }
}
