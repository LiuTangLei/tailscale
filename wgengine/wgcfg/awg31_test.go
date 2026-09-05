// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package wgcfg

import (
	"github.com/LiuTangLei/wireguard-go/device"
	"strings"
	"tailscale.com/ipn"
	"testing"
)

func TestApplyAmnezia31ThenReset(t *testing.T) {
	d := NewDevice(newNilTun(), new(noopBind), device.NewLogger(device.LogLevelError, "test"))
	defer d.Close()
	for _, enabled := range []bool{true, false} {
		p := ipn.AmneziaWGPrefs{RandomTrailers: enabled, DisableCookies: enabled}
		if err := ApplyAmneziaConfig(d, p); err != nil {
			t.Fatal(err)
		}
		got, err := d.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		val := "0"
		if enabled {
			val = "1"
		}
		for _, name := range []string{"random_trailers", "disable_cookies"} {
			if !strings.Contains(got, name+"="+val+"\n") {
				t.Fatalf("missing %s=%s", name, val)
			}
		}
	}
}
