// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package wgtransport

import (
	"errors"
	"testing"

	"github.com/LiuTangLei/wireguard-go/conn"
)

func TestProductionLegacyFactoryCannotBypassModeGate(t *testing.T) {
	b := &testBackend{bind: conn.NewDefaultBind()}
	c := Config{Mode: QUIC, Factory: &testFactory{mode: QUIC, backend: b}}
	if _, err := Resolve(c, ""); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("injected factory bypassed production gate: %v", err)
	}
	if _, err := New(Host{Bind: b.bind}, c); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("manager bypassed production gate: %v", err)
	}
	if b.closes != 0 {
		t.Fatal("legacy factory was constructed before rejection")
	}
	if _, err := Resolve(Config{Mode: Native}, string(QUIC)); err != nil {
		t.Fatalf("explicit native compatibility was broken: %v", err)
	}
}
