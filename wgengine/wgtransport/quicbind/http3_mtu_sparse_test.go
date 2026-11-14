package quicbind

import (
	"bytes"
	"encoding/hex"
	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestHTTP3SparseMTUBlackholeRecoversWithoutRehandshake(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", smallInitial, func(c *Config) { c.AutoTrust = true })
	var links [2]*mtuLimitedBind
	for i := range links {
		links[i] = &mtuLimitedBind{Bind: pair.bases[i].Bind}
		links[i].limit.Store(1500)
		pair.bases[i].Bind = links[i]
	}
	receive := pair.open(t)
	var endpoints [2]conn.Endpoint
	for i := range endpoints {
		raw := pair.keys[i^1].Public().Raw32()
		var err error
		endpoints[i], err = pair.backends[i].Bind().ParseEndpoint(hex.EncodeToString(raw[:]))
		require.NoError(t, err)
	}
	exchange := func() {
		for i := range 2 {
			require.NoError(t, pair.backends[i].Bind().Send([][]byte{{1, 2, 3}}, endpoints[i], 0))
			require.Equal(t, []byte{1, 2, 3}, readOne(t, receive[i^1]))
		}
	}
	exchange()
	_, sessions := sessionsOf(t, pair)
	pumpUntil(t, "1320 never reached", exchange, func() bool { return sessions[0].q.PacketSize() == 1320 && sessions[1].q.PacketSize() == 1320 })
	var counts [2]uint64
	for i := range links {
		counts[i] = pair.backends[i].counters.Connections.Load()
		links[i].limit.Store(1200)
	}
	full := bytes.Repeat([]byte{0x45}, 1280)
	// The first accepted unreliable datagram may be discarded by the actual
	// failed host write. Fresh packets must use carrier fragmentation afterward.
	for i := range 2 {
		require.NoError(t, pair.backends[i].Bind().Send([][]byte{full}, endpoints[i], 0))
	}
	require.Eventually(t, func() bool { return sessions[0].q.PacketSize() == 1200 && sessions[1].q.PacketSize() == 1200 }, 2*time.Second, 5*time.Millisecond, "silent sparse MTU black hole did not withdraw the established size")
	for i := range 2 {
		require.Positive(t, links[i].drops.Load())
		before := pair.backends[i].counters.FragmentedPackets.Load()
		require.NoError(t, pair.backends[i].Bind().Send([][]byte{full}, endpoints[i], 0))
		require.Equal(t, full, readOne(t, receive[i^1]))
		require.Greater(t, pair.backends[i].counters.FragmentedPackets.Load(), before)
		require.Equal(t, counts[i], pair.backends[i].counters.Connections.Load(), "fallback must preserve the authenticated session")
		require.NoError(t, sessions[i].q.Context().Err())
		require.Equal(t, "bbr-v3", sessions[i].q.ConnectionStats().CongestionControl)
	}
}
