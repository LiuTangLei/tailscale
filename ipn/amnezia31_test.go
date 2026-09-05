// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package ipn

import (
	"encoding/json"
	"testing"
)

func TestAmnezia31JSONAndClassification(t *testing.T) {
	for _, input := range []string{`{"RandomTrailers":true,"DisableCookies":true}`, `{"random_trailers":true,"disable_cookies":true}`} {
		var p AmneziaWGPrefs
		if err := json.Unmarshal([]byte(input), &p); err != nil {
			t.Fatal(err)
		}
		if !p.RandomTrailers || !p.DisableCookies || !p.IsV31() || !p.IsV3() || p.IsZero() {
			t.Fatalf("lost flags: %+v", p)
		}
		encoded, err := MarshalAmneziaWGConfigForDisco(p)
		if err != nil {
			t.Fatal(err)
		}
		var q AmneziaWGPrefs
		if err := json.Unmarshal(encoded, &q); err != nil || q != p {
			t.Fatalf("roundtrip %v %+v", err, q)
		}
		if err := json.Unmarshal([]byte(`{"random_trailers":false,"disable_cookies":false}`), &q); err != nil || !q.IsZero() {
			t.Fatalf("reset %v %+v", err, q)
		}
	}
	var p AmneziaWGPrefs
	if err := json.Unmarshal([]byte(`{"random_trailers":"true"}`), &p); err == nil {
		t.Fatal("accepted malformed boolean")
	}
}
