package quicbind

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/nettest"
)

// The full net.Conn contract belongs at the HTTP framing boundary. Using the
// direct test Bind keeps nettest's fixed 60-second/1000-message fixture independent
// of operating-system interface discovery and magicsock path-selection delays.
// Separate tailcat and WAN tests cover the full production discovery path.
func TestH3TCPConnContract(t *testing.T) {
	nettest.TestConn(t,func()(net.Conn,net.Conn,func(),error){
		accepted:=make(chan net.Conn,1)
		hold:=make(chan struct{})
		index:=0
		pair:=newTestPair(t,"http3-magicsock",func(c *Config){
			c.AutoTrust,c.TCPStreams,c.BBRv3=true,true,true
			c.Peers=nil;c.Server=index==1;c.TCPNodeAddress=tcpTestAddress
			c.AuthenticationSecret=[32]byte{3,8,4}
			if index==1 {c.TCPHandler=func(_ [32]byte,_ netip.AddrPort)func(net.Conn){return func(c net.Conn){accepted<-c;<-hold}}}
			index++
		})
		pair.open(t)
		ctx,cancel:=context.WithTimeout(t.Context(),10*time.Second)
		defer cancel()
		remote:=pair.keys[1].Public().Raw32()
		client,err:=pair.backends[0].DialTCPStream(ctx,remote,netip.AddrPortFrom(tcpTestAddress(remote),8080))
		if err!=nil {close(hold);return nil,nil,nil,err}
		var server net.Conn
		select{case server=<-accepted:case <-ctx.Done():close(hold);client.Close();return nil,nil,nil,ctx.Err()}
		var once sync.Once
		cleanup:=func(){once.Do(func(){client.Close();server.Close();close(hold);pair.backends[0].Close();pair.backends[1].Close()})}
		return client,server,cleanup,nil
	})
}
