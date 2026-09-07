// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

type menuTransportClient struct {
	state  ipn.TransportControlStatus
	writes []ipn.TransportControlRequest
}

func (c *menuTransportClient) TransportStatus(context.Context) (ipn.TransportControlStatus, error) {
	return c.state, nil
}
func (c *menuTransportClient) ConfigureTransport(_ context.Context, r ipn.TransportControlRequest) (ipn.TransportControlStatus, error) {
	c.writes = append(c.writes, r)
	if r.Action == "mode" {
		c.state.DesiredMode = r.Mode
		c.state.PendingRestart = c.state.ActiveMode != r.Mode
	}
	if r.Action == "prepare" {
		c.state.Identity = &ipn.TransportPeer{PublicKey: "public", SPKISHA256: "pin"}
	}
	return c.state, nil
}
func menuClient() *menuTransportClient {
	return &menuTransportClient{state: ipn.TransportControlStatus{ActiveMode: "native", DesiredMode: "native", Available: true, Source: "managed", Revision: "revision-7"}}
}
func TestStageTransportConfirmationAndCAS(t *testing.T) {
	for _, input := range []string{"", "\n", "n\n", "invalid\nn\n"} {
		c := menuClient()
		var out bytes.Buffer
		if err := stageTransportMode(context.Background(), c, "quic-ip", false, strings.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		if len(c.writes) != 0 {
			t.Fatalf("cancel/EOF mutated: %q", input)
		}
	}
	c := menuClient()
	var out bytes.Buffer
	if err := stageTransportMode(context.Background(), c, "http3-ip", false, strings.NewReader("y\n"), &out); err != nil {
		t.Fatal(err)
	}
	if len(c.writes) != 1 || c.writes[0].Action != "mode" || c.writes[0].Mode != "http3-ip" || c.writes[0].AutoTrust == nil || !*c.writes[0].AutoTrust || c.state.ActiveMode != "native" || !c.state.PendingRestart {
		t.Fatalf("wrong staged request %+v", c)
	}
	if !strings.Contains(out.String(), "NOT restart") || !strings.Contains(out.String(), "experimental") {
		t.Fatal("missing safety preview")
	}
}
func TestStageTransportRejectsBeforeWrite(t *testing.T) {
	for _, setup := range []func(*menuTransportClient){func(c *menuTransportClient) { c.state.Source = "environment" }, func(c *menuTransportClient) { c.state.Available = false }, func(c *menuTransportClient) { c.state.AWGConfigured = true }} {
		c := menuClient()
		setup(c)
		if err := stageTransportMode(context.Background(), c, "quic-ip", true, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal("invalid state accepted")
		}
		if len(c.writes) != 0 {
			t.Fatal("blocked action called mutation API")
		}
	}
}
func TestInteractiveIdentityExplicitInit(t *testing.T) {
	for _, input := range []string{"", "n\n", "\n"} {
		c := menuClient()
		if err := interactiveTransportIdentity(context.Background(), c, bufio.NewReader(strings.NewReader(input)), &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if len(c.writes) > 0 {
			t.Fatal("unconfirmed identity generation")
		}
	}
	c := menuClient()
	var out bytes.Buffer
	if err := interactiveTransportIdentity(context.Background(), c, bufio.NewReader(strings.NewReader("y\n")), &out); err != nil {
		t.Fatal(err)
	}
	if len(c.writes) != 1 || c.writes[0].Action != "prepare" || c.writes[0].ExpectedRevision != "revision-7" {
		t.Fatal("wrong init request")
	}
	if strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatal("secret printed")
	}
}
func TestInteractivePeerImportPreservesReader(t *testing.T) {
	peer := ipn.TransportPeer{PublicKey: strings.Repeat("ab", 32), SPKISHA256: strings.Repeat("cd", 32)}
	data, _ := json.Marshal(peer)
	reader := bufio.NewReader(strings.NewReader("1\n" + string(data) + "\ny\n9\n"))
	c := menuClient()
	if err := interactiveTransportPeers(context.Background(), c, reader, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(c.writes) != 1 || c.writes[0].Peer == nil || *c.writes[0].Peer != peer || c.writes[0].ExpectedRevision != "revision-7" {
		t.Fatal("wrong trust request")
	}
	next, _ := readLine(reader)
	if next != "9" {
		t.Fatal("submenu swallowed root-menu input")
	}
}
func TestPeerCardRejectsTrailingUnknownOversize(t *testing.T) {
	valid := `{"public_key":"key","spki_sha256":"pin"}`
	for _, bad := range []string{valid + valid, `{"public_key":"key","spki_sha256":"pin","private_key":"secret"}`, `{"public_key":"x","public_key":"y","spki_sha256":"z"}`, strings.Repeat("x", (16<<10)+1), `{"public_key":"key"}`} {
		if _, err := parseTransportPeerJSON(bad); err == nil {
			t.Fatal("invalid card accepted")
		}
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTTY(f) {
		t.Fatal("/dev/null mistaken for interactive terminal")
	}
}
