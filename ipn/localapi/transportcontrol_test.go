// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package localapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPacketTransportPermissionAndBody(t *testing.T) {
	for _, tc := range []struct {
		method, body string
		read, write  bool
		want         int
	}{
		{http.MethodGet, "", false, false, 403},
		{http.MethodPost, `{"action":"mode"}`, true, false, 403},
		{http.MethodDelete, "", true, true, 405},
		{http.MethodPost, `{"action":"prepare","private_key":"secret"}`, true, true, 400},
		{http.MethodPost, `{"action":"prepare"}{"action":"mode"}`, true, true, 400},
		{http.MethodPost, strings.Repeat("x", 17<<10), true, true, 400},
	} {
		t.Run(tc.method+tc.body[:min(len(tc.body), 15)], func(t *testing.T) {
			h := &Handler{PermitRead: tc.read, PermitWrite: tc.write}
			req := httptest.NewRequest(tc.method, "http://local-tailscaled.sock/localapi/v0/packet-transport", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			h.servePacketTransport(w, req)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
			if strings.Contains(w.Body.String(), "secret") {
				t.Fatal("echoed sensitive body")
			}
		})
	}
}

func TestPacketTransportDiagnosticsPermissionAndMethod(t *testing.T) {
	for _, tc := range []struct {
		method      string
		read, write bool
		want        int
	}{
		{http.MethodGet, false, false, http.StatusForbidden},
		{http.MethodPost, true, true, http.StatusMethodNotAllowed},
		{http.MethodDelete, true, true, http.StatusMethodNotAllowed},
	} {
		h := &Handler{PermitRead: tc.read, PermitWrite: tc.write}
		w := httptest.NewRecorder()
		h.servePacketTransportDiagnostics(w, httptest.NewRequest(tc.method, "/localapi/v0/packet-transport-stats", nil))
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: got %d, headers %v", tc.method, w.Code, w.Header())
		}
	}
}
