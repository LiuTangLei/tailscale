package tstun

import (
	"bytes"
	"fmt"
	"testing"

	"encoding/binary"
	"github.com/LiuTangLei/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func overlapTCPRecord(version, payloadSize, count int, flags byte) ([]byte, tun.GSOOptions) {
	ipLen := 20
	gso := tun.GSOTCPv4
	if version == 6 {
		ipLen = 40
		gso = tun.GSOTCPv6
	}
	packet := make([]byte, ipLen+20+payloadSize*count)
	if version == 4 {
		packet[0] = 0x45
		packet[8] = 64
		packet[9] = 6
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[4:], 0xfff0)
		copy(packet[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	} else {
		packet[0] = 0x60
		packet[6] = 6
		packet[7] = 64
		binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
		copy(packet[8:12], []byte{0x20, 1, 0x0d, 0xb8})
		packet[23] = 1
		copy(packet[24:28], []byte{0x20, 1, 0x0d, 0xb8})
		packet[39] = 2
	}
	binary.BigEndian.PutUint16(packet[ipLen:], 1234)
	binary.BigEndian.PutUint16(packet[ipLen+2:], 443)
	binary.BigEndian.PutUint32(packet[ipLen+4:], 0xfffff000)
	packet[ipLen+12] = 0x50
	packet[ipLen+13] = flags
	for i := ipLen + 20; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	return packet, tun.GSOOptions{GSOType: gso, HdrLen: uint16(ipLen + 20), GSOSize: uint16(payloadSize), CsumStart: uint16(ipLen), CsumOffset: 16, NeedsCsum: true}
}

func overlapOutputs(count, capacity int) ([][]byte, []int) {
	bufs := make([][]byte, count)
	for i := range bufs {
		bufs[i] = make([]byte, 16+capacity)
	}
	return bufs, make([]int, count)
}

type gsoContractWriter struct {
	tun.Device
	packets [][]byte
}

func (w *gsoContractWriter) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		w.packets = append(w.packets, bytes.Clone(b[offset:]))
	}
	return len(bufs), nil
}

func TestActualInjectInboundGSOOverlapFlags(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, payload := range []int{64, 1400} {
			for _, count := range []int{1, 2, 4, 32} {
				for _, flags := range []byte{0x10, 0x11, 0x18, 0x19} {
					t.Run(fmt.Sprintf("v%d-payload%d-N%d-flags%x", version, payload, count, flags), func(t *testing.T) {
						raw, opts := overlapTCPRecord(version, payload, count, flags)
						want, ws := overlapOutputs(count, len(raw))
						n, err := tun.GSOSplit(bytes.Clone(raw), opts, want, ws, PacketStartOffset)
						if err != nil || n != count {
							t.Fatalf("disjoint %d %v", n, err)
						}
						ipLen := 20
						gsoType := stack.GSOTCPv4
						if version == 6 {
							ipLen = 40
							gsoType = stack.GSOTCPv6
						}
						pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(raw))})
						if _, ok := pkt.NetworkHeader().Consume(ipLen); !ok {
							t.Fatal("network header")
						}
						if _, ok := pkt.TransportHeader().Consume(20); !ok {
							t.Fatal("transport header")
						}
						pkt.GSOOptions = stack.GSO{Type: gsoType, L3HdrLen: uint16(ipLen), MSS: uint16(payload), CsumOffset: 16, NeedsCsum: true}
						writer := &gsoContractWriter{}
						w := &Wrapper{tdev: writer}
						bufs, sizes := overlapOutputs(count, len(raw))
						if err := w.InjectInboundPacketBuffer(pkt, bufs, sizes); err != nil {
							t.Fatal(err)
						}
						if len(writer.packets) != count {
							t.Fatalf("written %d want %d", len(writer.packets), count)
						}
						for i := range writer.packets {
							if !bytes.Equal(writer.packets[i], want[i][PacketStartOffset:PacketStartOffset+ws[i]]) {
								t.Errorf("actual InjectInbound overlap differs segment%d/%d TCPflags got=%x want=%x", i, count, writer.packets[i][ipLen+13], want[i][PacketStartOffset+ipLen+13])
							}
							if len(bufs[i]) != cap(bufs[i]) {
								t.Error("caller length not restored")
							}
						}
					})
				}
			}
		}
	}
}
