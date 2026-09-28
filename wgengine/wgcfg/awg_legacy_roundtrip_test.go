// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package wgcfg

import (
	"encoding/json"
	"github.com/LiuTangLei/wireguard-go/device"
	"strings"
	"tailscale.com/ipn"
	"testing"
)

func TestLegacyAWG2JSONSurvivesV31AndNativeTransitions(t *testing.T) {
	for _, headers := range []string{
		`"h1":1001,"h2":2001,"h3":3001,"h4":4001`,
		`"h1":"1001-1010","h2":"2001-2010","h3":"3001-3010","h4":"4001-4010"`,
	} {
		raw := `{"jc":2,"jmin":64,"jmax":128,"s1":5,"s2":7,"s3":9,"s4":11,"i1":"<r 8>","i2":"<b 0x01020304>",` + headers + `}`
		var legacy ipn.AmneziaWGPrefs
		if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
			t.Fatal(err)
		}
		if err := ipn.ValidateAmneziaWGConfig(legacy); err != nil {
			t.Fatal(err)
		}
		d := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "legacy test"))
		if err := ApplyAmneziaConfig(d, legacy); err != nil {
			d.Close()
			t.Fatal(err)
		}
		baseline, err := d.IpcGet()
		if err != nil {
			d.Close()
			t.Fatal(err)
		}
		modern := legacy
		modern.S1, modern.S2, modern.S3, modern.S4 = 16, 20, 24, 28
		modern.HeaderProtectionKey = strings.Repeat("42", device.HeaderCipherKeySize)
		modern.ContentPaddingAddition = ipn.MagicHeaderRange{Min: 4, Max: 12}
		modern.RandomTrailers, modern.DisableCookies = true, true
		for round := 0; round < 3; round++ {
			if err := ApplyAmneziaConfig(d, modern); err != nil {
				d.Close()
				t.Fatal(err)
			}
			if err := ApplyAmneziaConfig(d, legacy); err != nil {
				d.Close()
				t.Fatal(err)
			}
			got, err := d.IpcGet()
			if err != nil {
				d.Close()
				t.Fatal(err)
			}
			if got != baseline {
				d.Close()
				t.Fatalf("v2 -> v3.1 -> v2 left different state in round %d", round)
			}
			for _, flag := range []string{"random_trailers=0\n", "disable_cookies=0\n"} {
				if !strings.Contains(got, flag) {
					d.Close()
					t.Fatalf("stale modern flag %s", flag)
				}
			}
		}
		if err := ApplyAmneziaConfig(d, ipn.AmneziaWGPrefs{}); err != nil {
			d.Close()
			t.Fatal(err)
		}
		got, err := d.IpcGet()
		d.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, stale := range []string{"header_protection_key=", "content_padding_addition=", "i1=<r 8>", "i2=<b 0x01020304>"} {
			if strings.Contains(got, stale) {
				t.Fatalf("native retained %s", stale)
			}
		}
	}
}
