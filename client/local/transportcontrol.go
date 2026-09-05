// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package local

import (
	"context"
	"encoding/json"
	"net/http"
	"tailscale.com/ipn"
)

func (lc *Client) TransportStatus(ctx context.Context) (ipn.TransportControlStatus, error) {
	var status ipn.TransportControlStatus
	data, err := lc.get200(ctx, "/localapi/v0/packet-transport")
	if err != nil {
		return status, err
	}
	err = json.Unmarshal(data, &status)
	return status, err
}
func (lc *Client) ConfigureTransport(ctx context.Context, req ipn.TransportControlRequest) (ipn.TransportControlStatus, error) {
	var status ipn.TransportControlStatus
	data, err := lc.send(ctx, http.MethodPost, "/localapi/v0/packet-transport", http.StatusOK, jsonBody(req))
	if err != nil {
		return status, err
	}
	err = json.Unmarshal(data, &status)
	return status, err
}
