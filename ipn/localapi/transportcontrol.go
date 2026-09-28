// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package localapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"tailscale.com/ipn"
	"tailscale.com/wgengine/transportprofile"
)

func (h *Handler) servePacketTransport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if (r.Method == http.MethodGet && !h.PermitRead && !h.PermitWrite) || (r.Method == http.MethodPost && !h.PermitWrite) {
		http.Error(w, "transport configuration access denied", http.StatusForbidden)
		return
	}
	var status ipn.TransportControlStatus
	var err error
	if r.Method == http.MethodGet {
		status, err = h.b.TransportStatus()
	} else {
		var req ipn.TransportControlRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, "invalid transport request", http.StatusBadRequest)
			return
		}
		if dec.Decode(new(any)) != io.EOF {
			http.Error(w, "expected one transport request", http.StatusBadRequest)
			return
		}
		status, err = h.b.ConfigureTransport(r.Context(), req)
	}
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, transportprofile.ErrConflict) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
