package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestAWGRootMenuDispatchCancelEOF(t *testing.T) {
	var out bytes.Buffer
	if err := runAWGRootMenu(context.Background(), strings.NewReader("9\n"), &out, true, &out); err != nil {
		t.Fatalf("runAWGRootMenu returned %v", err)
	}
	if !strings.Contains(out.String(), "Tailscale AWG") {
		t.Fatalf("root menu output = %q, want banner", out.String())
	}
}

func TestAWGNoTTYHelp(t *testing.T) {
	var out bytes.Buffer
	if err := runAWGRootMenu(context.Background(), strings.NewReader(""), &out, false, &out); err != nil {
		t.Fatalf("runAWGRootMenu returned %v", err)
	}
	if !strings.Contains(out.String(), "Usage: tailscale awg") {
		t.Fatalf("non-TTY output = %q, want help", out.String())
	}
}

func TestAWGTransportModeRejectsInvalidMode(t *testing.T) {
	var out bytes.Buffer
	err := runAWGTransportMode(context.Background(), "quic", false, strings.NewReader("y\n"), &out)
	if err == nil || !strings.Contains(err.Error(), "supported values are native") {
		t.Fatalf("runAWGTransportMode error = %v, want invalid mode message", err)
	}
}

func TestAWGTransportStatusRenderPendingNotActive(t *testing.T) {
	var out bytes.Buffer
	status := ipn.TransportControlStatus{
		ActiveMode:     "native",
		DesiredMode:    "quic-ip",
		PendingRestart: true,
		Source:         "environment",
		AWGConfigured:  true,
		Warnings:       []string{"HTTP3 is experimental"},
	}
	if err := renderTransportStatus(status, &out, false); err != nil {
		t.Fatalf("renderTransportStatus returned %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"Active mode: native",
		"Desired mode: quic-ip",
		"Pending restart: yes",
		"Source: environment",
		"HTTP3 is experimental",
		"Reset AWG explicitly",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("render output = %q, missing %q", got, want)
		}
	}
}

func TestAWGIdentityJSONNoSecrets(t *testing.T) {
	peer := &ipn.TransportPeer{
		Name:       "relay",
		PublicKey:  "public-key",
		SPKISHA256: "sha256",
		HTTP3URL:   "https://example.com/masque",
	}
	var out bytes.Buffer
	if err := renderIdentityJSON(peer, &out); err != nil {
		t.Fatalf("renderIdentityJSON error = %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "\"public_key\":\"public-key\"") {
		t.Fatalf("JSON output = %q, want public_key", got)
	}
	if strings.Contains(got, "private_key") {
		t.Fatalf("JSON output = %q, must not include private key", got)
	}
}

func TestTransportModeRequestIncludesExpectedRevision(t *testing.T) {
	status := ipn.TransportControlStatus{Revision: "rev-42"}
	req := transportModeRequest(status, "quic-ip")
	if req.Action != "mode" || req.ExpectedRevision != "rev-42" || req.Mode != "quic-ip" {
		t.Fatalf("request = %#v, want mode request with CAS revision", req)
	}
}
