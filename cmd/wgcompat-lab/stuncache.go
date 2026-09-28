// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/atomicfile"
	"tailscale.com/tailcfg"
)

// The isolated test uses this map for STUN destinations only, not as a control
// server or public relay. Reuse a recently fetched map so each benchmark does
// not depend on an unrelated HTTPS handshake succeeding at that instant.
func loadLabSTUNMap(ctx context.Context) (*tailcfg.DERPMap, error) {
	cache := ""
	if root, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(root, "tailscale-transport-lab", "stun-map.json")
	}
	if st, err := os.Stat(cache); err == nil && time.Since(st.ModTime()) < 24*time.Hour && st.Size() <= 2<<20 {
		if data, err := os.ReadFile(cache); err == nil {
			var m tailcfg.DERPMap
			if json.Unmarshal(data, &m) == nil && len(m.Regions) > 0 {
				return &m, nil
			}
		}
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req, _ := http.NewRequestWithContext(attemptCtx, http.MethodGet, "https://controlplane.tailscale.com/derpmap/default", nil)
		res, err := http.DefaultClient.Do(req)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
			res.Body.Close()
			if readErr != nil {
				err = readErr
			} else if res.StatusCode != http.StatusOK || len(data) > 2<<20 {
				err = fmt.Errorf("STUN map HTTP %d or oversized body", res.StatusCode)
			} else {
				var m tailcfg.DERPMap
				if err = json.Unmarshal(data, &m); err == nil && len(m.Regions) > 0 {
					cancel()
					if cache != "" && os.MkdirAll(filepath.Dir(cache), 0700) == nil {
						_ = atomicfile.WriteFile(cache, data, 0600)
					}
					return &m, nil
				}
			}
		}
		cancel()
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("load public STUN map: %w", last)
}
