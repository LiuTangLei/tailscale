// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"tailscale.com/tailcfg"
)

// addPublicSTUN gives real hosts usable UDP probes without using a public relay
// or registering them with a production control plane. Otherwise a relay-only
// test map reports IPv4CanSend=false and repeatedly triggers magicsock rebinds.
func addPublicSTUN(ctx context.Context, dst *tailcfg.DERPMap) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://controlplane.tailscale.com/derpmap/default", nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("load public STUN map: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("public STUN map HTTP %d", res.StatusCode)
	}
	var public tailcfg.DERPMap
	if err := json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&public); err != nil {
		return err
	}
	return attachSTUNNodes(dst, &public)
}

func attachSTUNNodes(dst, public *tailcfg.DERPMap) error {
	region := dst.Regions[901]
	if region == nil {
		return errors.New("missing isolated lab relay region")
	}
	ids := make([]int, 0, len(public.Regions))
	for id := range public.Regions {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var nodes []*tailcfg.DERPNode
	for _, id := range ids {
		r := public.Regions[id]
		if r == nil {
			continue
		}
		for _, n := range r.Nodes {
			if n == nil || n.STUNPort < 0 {
				continue
			}
			copy := *n
			copy.Name = "wgcompat-stun-" + n.Name
			copy.RegionID = region.RegionID
			copy.STUNOnly = true
			copy.InsecureForTests = false
			copy.STUNTestIP = ""
			nodes = append(nodes, &copy)
			break // one distinct public destination per region
		}
		if len(nodes) == 6 {
			break
		}
	}
	if len(nodes) == 0 {
		return errors.New("public map contains no STUN servers")
	}
	// Keep them in the lab region: netcheck must not elect a STUN-only region
	// as the preferred DERP. Actual relay traffic still uses only our SSH link.
	region.Nodes = append(nodes, region.Nodes...)
	return nil
}
