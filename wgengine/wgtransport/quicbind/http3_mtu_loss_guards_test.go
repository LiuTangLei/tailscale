package quicbind

import (
	"bytes"
	"encoding/hex"
	"github.com/LiuTangLei/wireguard-go/conn"
	"github.com/stretchr/testify/require"
	"sync/atomic"
	"testing"
	"time"
)

type smallPacketDropBind struct {
	conn.Bind
	armed atomic.Bool
	drops atomic.Int64
}

func (b *smallPacketDropBind) Send(packets [][]byte, endpoint conn.Endpoint, offset int) error {
	accepted := make([][]byte, 0, len(packets))
	for _, p := range packets {
		size := len(p) - offset
		if size >= 400 && size <= 1000 && b.armed.CompareAndSwap(true, false) {
			b.drops.Add(1)
			continue
		}
		accepted = append(accepted, p)
	}
	if len(accepted) == 0 {
		return nil
	}
	return b.Bind.Send(accepted, endpoint, offset)
}
func TestHTTP3TransientLargerLossKeepsConfirmedSize(t *testing.T) {
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
	// Intentionally discard only the first application datagram of each side.
	for i := range 2 {
		require.NoError(t, pair.backends[i].Bind().Send([][]byte{full}, endpoints[i], 0))
	}

	require.Eventually(t, func() bool { return links[0].drops.Load() > 0 && links[1].drops.Load() > 0 }, time.Second, time.Millisecond)
	for i := range links {
		links[i].limit.Store(1500)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for i := range sessions {
			require.Equal(t, 1200+120, sessions[i].q.PacketSize(), "transient loss must not immediately withdraw a confirmed size")
			require.Equal(t, counts[i], pair.backends[i].counters.Connections.Load())
			require.NoError(t, sessions[i].q.Context().Err())
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i := range 2 {
		require.NoError(t, pair.backends[i].Bind().Send([][]byte{full}, endpoints[i], 0))
		require.Equal(t, full, readOne(t, receive[i^1]))
	}
}
func TestHTTP3SmallPacketLossKeepsConfirmedSize(t *testing.T) {
	pair := newTestPair(t, "http3-magicsock", smallInitial, func(c *Config) { c.AutoTrust = true })
	var links [2]*smallPacketDropBind
	for i := range links {
		links[i] = &smallPacketDropBind{Bind: pair.bases[i].Bind}
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
		links[i].armed.Store(true)
	}
	full := bytes.Repeat([]byte{0x45}, 500)
	// Intentionally discard only the first application datagram of each side.
	for i := range 2 {
		require.NoError(t, pair.backends[i].Bind().Send([][]byte{full}, endpoints[i], 0))
	}

	require.Eventually(t, func() bool { return links[0].drops.Load() == 1 && links[1].drops.Load() == 1 }, time.Second, time.Millisecond)
	// Later delivered packet numbers drive real loss detection while the path
	// continues to carry target-sized probes.
	for range 4 {
		exchange()
	}
	require.Eventually(t, func() bool {
		return sessions[0].q.ConnectionStats().PacketsLost > 0 && sessions[1].q.ConnectionStats().PacketsLost > 0
	}, time.Second, time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for i := range sessions {
			require.Equal(t, 1320, sessions[i].q.PacketSize(), "small-packet loss cannot establish an MTU black hole")
			require.Equal(t, counts[i], pair.backends[i].counters.Connections.Load())
			require.NoError(t, sessions[i].q.Context().Err())
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i := range 2 {
		require.NoError(t, pair.backends[i].Bind().Send([][]byte{full}, endpoints[i], 0))
		require.Equal(t, full, readOne(t, receive[i^1]))
	}
	for i := range sessions {
		require.Positive(t, sessions[i].q.ConnectionStats().PacketsLost, "the ordinary data loss must have been detected")
	}
}
