// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"encoding/json"
	"strings"
	"tailscale.com/ipn"
	"testing"
)

func TestAWG31CanonicalJSON(t *testing.T) {
	p := ipn.AmneziaWGPrefs{RandomTrailers: true, DisableCookies: true}
	text, err := formatConfigAsJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `"random_trailers":true`) || !strings.Contains(text, `"disable_cookies":true`) {
		t.Fatalf("lost 3.1 flags: %s", text)
	}
	var got ipn.AmneziaWGPrefs
	if err := json.Unmarshal([]byte(text), &got); err != nil || got != p {
		t.Fatalf("roundtrip=%+v err=%v", got, err)
	}
	if version := amneziaConfigVersion(got); version != "AWG v3.1" {
		t.Fatalf("version=%s", version)
	}
	zero, err := formatConfigAsJSON(ipn.AmneziaWGPrefs{})
	if err != nil || zero != "{}" {
		t.Fatalf("standard=%s err=%v", zero, err)
	}
}
