// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package nodeauth

import (
	"bytes"
	"os"
	"os/exec"
	"tailscale.com/types/key"
	"testing"
)

func TestHandshakeConfirmationReplayAndClose(t *testing.T) {
	a, b := key.NewNode(), key.NewNode()
	valid := func([32]byte) bool { return true }
	initiator, err := New(a, b.Public().Raw32(), true, make([]byte, 32), valid)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	responder, err := New(b, [32]byte{}, false, make([]byte, 32), valid)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	exchange := func(from, to Handshake, msg string) []byte {
		wire, err := from.Write([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := to.Read(wire)
		if err != nil || !bytes.Equal(plain, []byte(msg)) {
			t.Fatal("handshake message failed", err)
		}
		return wire
	}
	exchange(initiator, responder, "request")
	exchange(responder, initiator, "reply")
	confirmation := exchange(initiator, responder, "client finished")
	exchange(responder, initiator, "server finished")
	if _, err := responder.Read(confirmation); err == nil {
		t.Fatal("confirmation replay accepted")
	}
	initiator.Close()
	if _, err := initiator.Write([]byte("closed")); err == nil {
		t.Fatal("closed key state usable")
	}
	if _, err := initiator.Read(confirmation); err == nil {
		t.Fatal("closed key state usable")
	}
}
func TestFIPSPolicy(t *testing.T) {
	if os.Getenv("TS_TEST_NODEAUTH_FIPS_CHILD") == "1" {
		_, err := New(key.NewNode(), [32]byte{}, false, make([]byte, 32), func([32]byte) bool { return true })
		if err == nil {
			t.Fatal("Noise ChaCha suite accepted under FIPS-only policy")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPSPolicy$")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", "TS_TEST_NODEAUTH_FIPS_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("FIPS refusal crashed: %v\n%s", err, out)
	}
}
