// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package wgtransport

import (
	"errors"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
)

func TestProductionLegacyFactoryCannotBypassModeGate(t *testing.T) {
	for _, mode := range []Mode{QUIC, QUICIP} {
		t.Run(string(mode), func(t *testing.T) {
			b := &testBackend{bind: conn.NewDefaultBind()}
			c := Config{Mode: mode, Factory: &testFactory{mode: mode, backend: b}}
			if _, err := Resolve(c, ""); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("injected factory bypassed production gate: %v", err)
			}
			if _, err := New(Host{Bind: b.bind}, c); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("manager bypassed production gate: %v", err)
			}
			if b.closes != 0 {
				t.Fatal("legacy factory was constructed before rejection")
			}
			if _, err := Resolve(Config{Mode: Native}, string(mode)); err != nil {
				t.Fatalf("explicit native compatibility was broken: %v", err)
			}
		})
	}
}
