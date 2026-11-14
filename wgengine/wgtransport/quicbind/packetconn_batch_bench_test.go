package quicbind

import (
	"fmt"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
	"tailscale.com/wgengine/wgtransport"
)

type discardBatchBind struct{ conn.Bind }

func (*discardBatchBind) BatchSize() int { return maxOuterPacketBatch }
func (*discardBatchBind) Send(packets [][]byte, _ conn.Endpoint, offset int) error {
	for _, p := range packets {
		p[offset-1] = 1
	} // borrowed relay headroom
	return nil
}
func BenchmarkPacketConnReadyBatch(b *testing.B) {
	for _, count := range []int{2, 8, 32} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			c := newBindPacketConn(&generation{b: &Backend{host: wgtransport.Host{Bind: &discardBatchBind{}}}})
			defer c.Close()
			input := make([][]byte, count)
			for i := range input {
				input[i] = make([]byte, 1200)
			}
			addr := &bindAddr{ep: &endpoint{}}
			b.ReportAllocs()
			b.SetBytes(int64(count * 1200))
			b.ResetTimer()
			for b.Loop() {
				if err := c.WritePacketBatch(input, addr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
