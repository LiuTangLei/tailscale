package quicbind

import (
	"bytes"
	"testing"
	"time"
)

// A few lost DATAGRAM fragments must not block unrelated complete IP packets
// for the full reassembly timeout. The resource limit remains unchanged.
func TestLostFragmentsDoNotBlockNewPackets(t *testing.T) {
	var r reassembler
	now := time.Unix(1234, 0)
	for i := 0; i < maxAssemblies; i++ {
		if _, err := r.consume(fragment(uint32(i+1), 1280, 0, bytes.Repeat([]byte{1}, 1150)), now.Add(time.Duration(i))); err != nil {
			t.Fatal(err)
		}
	}
	want := bytes.Repeat([]byte{7}, 1280)
	for i := 0; i < 100; i++ {
		id := uint32(1000+i)
		if p, err := r.consume(fragment(id, len(want), 0, want[:1150]), now.Add(time.Millisecond)); err != nil || p != nil {
			t.Fatalf("new packet starved by abandoned fragments: %v", err)
		}
		got, err := r.consume(fragment(id, len(want), 1150, want[1150:]), now.Add(time.Millisecond))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("intact packet not delivered under fragment pressure: %v", err)
		}
		if len(r.messages) > maxAssemblies {
			t.Fatal("reassembly memory bound exceeded")
		}
	}
}

func TestFragmentPressureEvictsOldestOnly(t *testing.T) {
	var r reassembler
	now := time.Unix(1234, 0)
	for i := 0; i < maxAssemblies; i++ {
		_, err := r.consume(fragment(uint32(i+1), 6, 0, []byte("abc")), now.Add(time.Duration(i)*time.Millisecond))
		if err != nil { t.Fatal(err) }
	}
	if _, err := r.consume(fragment(100, 6, 0, []byte("abc")), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(r.messages) != maxAssemblies || r.messages[1] != nil {
		t.Fatal("oldest incomplete message was not replaced within capacity")
	}
	for i := 2; i <= maxAssemblies; i++ {
		got, err := r.consume(fragment(uint32(i), 6, 3, []byte("def")), now.Add(time.Second))
		if err != nil || string(got) != "abcdef" { t.Fatalf("newer message lost: %v", err) }
	}
}
