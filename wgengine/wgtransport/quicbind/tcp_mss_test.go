package quicbind

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func checksumForTest(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 { sum += uint32(binary.BigEndian.Uint16(p)); p=p[2:] }
	if len(p) != 0 { sum += uint32(p[0])<<8 }
	for sum>>16 != 0 { sum=(sum&65535)+(sum>>16) }
	return ^uint16(sum)
}

func mssPacketForTest(ipv6, odd bool, mss uint16) ([]byte, int) {
	offset := 20
	if ipv6 { offset=40 }
	p := make([]byte, offset+28)
	if ipv6 {
		p[0],p[6]=0x60,6
		binary.BigEndian.PutUint16(p[4:6],28)
	} else {
		p[0],p[9]=0x45,6
		binary.BigEndian.PutUint16(p[2:4],uint16(len(p)))
	}
	tcp:=p[offset:]
	tcp[12],tcp[13]=7<<4,2
	pos:=20
	if odd { tcp[pos]=1;pos++ }
	tcp[pos],tcp[pos+1]=2,4
	binary.BigEndian.PutUint16(tcp[pos+2:],mss)
	binary.BigEndian.PutUint16(tcp[16:18],checksumForTest(tcp))
	return p,offset
}

func TestTCPMSSClampChecksum(t *testing.T) {
	for _, v6:=range []bool{false,true} {
		for _, odd:=range []bool{false,true} {
			for _, old:=range []uint16{536,1080,1220,1460,65535} {
				p,off:=mssPacketForTest(v6,odd,old)
				before:=bytes.Clone(p)
				changed:=clampTCPMSS(p,1080)
				if changed != (old>1080) { t.Fatalf("wrong clamp decision for %d",old) }
				if checksumForTest(p[off:])!=0 { t.Fatalf("bad incremental checksum v6=%v odd=%v",v6,odd) }
				if !changed && !bytes.Equal(p,before) { t.Fatal("unchanged packet mutated") }
				if clampTCPMSS(p,1080) { t.Fatal("clamp not idempotent") }
			}
		}
	}
}

func TestTCPMSSClampRejectsMalformedAndNonSYN(t *testing.T) {
	for _, mutation:= range []func([]byte){
		func(p []byte){p[53]=0x10},
		func(p []byte){p[6]=17},
		func(p []byte){p[4]=255},
		func(p []byte){p[61]=1},
		func(p []byte){p[61]=20},
		func(p []byte){p[52]=15<<4},
		func(p []byte){copy(p[64:],[]byte{2,4,5,0})},
	} {
		p,_:=mssPacketForTest(true,false,1220)
		mutation(p)
		before:=bytes.Clone(p)
		if clampTCPMSS(p,1080) || !bytes.Equal(p,before) { t.Fatal("changed malformed/unsupported packet") }
	}
	p,_:=mssPacketForTest(false,false,1220)
	p[6]=0x20 // IP fragment flag
	if clampTCPMSS(p,1080) { t.Fatal("modified fragmented IPv4") }
}

func FuzzTCPMSSClamp(f *testing.F) {
	p,_:=mssPacketForTest(true,false,1220)
	f.Add(p)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T,p []byte){
		before:=bytes.Clone(p)
		changed:=clampTCPMSS(p,1080)
		if !changed && !bytes.Equal(p,before) { t.Fatal("partial modification on failure") }
		if changed && clampTCPMSS(p,1080) { t.Fatal("not idempotent") }
	})
}
