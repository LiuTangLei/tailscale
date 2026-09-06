// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestServerFlagCLIConfirmationAndCAS(t *testing.T) {
	for _, input := range []string{"", "\n", "n\n"} {
		c := menuClient()
		var out bytes.Buffer
		if err := stageServerDeclaration(context.Background(), c, "on", false, strings.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		if len(c.writes) != 0 {
			t.Fatal("cancel/EOF saved a server declaration")
		}
	}
	for _, enabled := range []bool{false, true} {
		c := menuClient()
		c.state.Server = !enabled
		var out bytes.Buffer
		value := "off"
		if enabled {
			value = "on"
		}
		if err := stageServerDeclaration(context.Background(), c, value, true, nil, &out); err != nil {
			t.Fatal(err)
		}
		if len(c.writes) != 1 {
			t.Fatal("missing single local mutation")
		}
		r := c.writes[0]
		if r.Action != "server" || r.Server == nil || *r.Server != enabled || r.ExpectedRevision != "revision-7" || r.PublicKey != "" || r.Peer != nil {
			t.Fatalf("unexpected per-peer update: %+v", r)
		}
		if !strings.Contains(out.String(), "NOT restart") {
			t.Fatal("missing restart notice")
		}
	}
}

func TestServerFlagCLIRejectsInvalidOrExternalConfiguration(t *testing.T) {
	c := menuClient()
	var out bytes.Buffer
	if err := stageServerDeclaration(context.Background(), c, "client", true, nil, &out); err == nil {
		t.Fatal("accepted old role option")
	}
	for _, source := range []string{"embedded", "environment"} {
		c.state.Source = source
		if err := stageServerDeclaration(context.Background(), c, "on", true, nil, &out); err == nil {
			t.Fatal("overrode external config")
		}
	}
	if len(c.writes) != 0 {
		t.Fatal("invalid update saved")
	}
	peer, err := parseTransportPeerJSON(`{"public_key":"test","spki_sha256":"pin","server":true}`)
	if err != nil || !peer.Server {
		t.Fatal("public hint lost", err)
	}
	if _, err := parseTransportPeerJSON(`{"public_key":"test","spki_sha256":"pin","server":true,"server":false}`); err == nil {
		t.Fatal("duplicate flag accepted")
	}
	for _, sub := range peerCommand().Subcommands {
		if sub.Name == "role" {
			t.Fatal("per-peer role configuration still exposed")
		}
	}
}
