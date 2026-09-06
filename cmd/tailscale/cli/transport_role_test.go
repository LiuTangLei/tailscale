// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestPeerRolePromptIsLocalStagedAndCancellable(t *testing.T) {
	k := strings.Repeat("ab", 32)
	for _, input := range []string{"", "\n", "n\n", "invalid\nn\n", "y\n"} {
		c := menuClient()
		c.state.Peers = []ipn.TransportPeer{{PublicKey: k, SPKISHA256: strings.Repeat("cd", 32)}}
		var out bytes.Buffer
		if err := stagePeerRole(context.Background(), c, "nodekey:"+k, "client", false, strings.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		if input != "y\n" {
			if len(c.writes) != 0 {
				t.Fatal("cancel changed roles")
			}
			continue
		}
		if len(c.writes) != 1 || c.writes[0].Action != "peer-role" || c.writes[0].ConnectionRole != "client" || c.writes[0].ExpectedRevision != "revision-7" {
			t.Fatalf("invalid request %+v", c.writes)
		}
		if c.state.ActiveMode != "native" {
			t.Fatal("role command switched running protocol")
		}
		if !strings.Contains(out.String(), "Both IP directions") || !strings.Contains(out.String(), "complementary") {
			t.Fatal("missing role semantics")
		}
	}
}

func TestPeerRoleRejectsUntrustedAndExternalBeforeMutation(t *testing.T) {
	for _, source := range []string{"managed", "environment", "embedded"} {
		c := menuClient()
		c.state.Source = source
		if err := stagePeerRole(context.Background(), c, "not-trusted", "server", true, nil, nil); err == nil {
			t.Fatal("bad role assignment accepted")
		}
		if len(c.writes) != 0 {
			t.Fatal("invalid request wrote config")
		}
	}
	if _, err := parseTransportPeerJSON(`{"public_key":"abc","spki_sha256":"def","connection_role":"client"}`); err == nil {
		t.Fatal("remote identity card can dictate local role")
	}
}
