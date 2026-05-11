// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/version/distro"
)

func withRestartTestHooks(t *testing.T, goos string, currentDistro distro.Distro, inContainer bool, command func(string, ...string) ([]byte, error)) {
	t.Helper()
	originalGOOS := restartGOOS
	originalDistro := restartDistro
	originalInContainer := restartInContainer
	originalCommand := restartCommand
	restartGOOS = func() string { return goos }
	restartDistro = func() distro.Distro { return currentDistro }
	restartInContainer = func() bool { return inContainer }
	restartCommand = command
	t.Cleanup(func() {
		restartGOOS = originalGOOS
		restartDistro = originalDistro
		restartInContainer = originalInContainer
		restartCommand = originalCommand
	})
}

func TestRestartTailscaledOpenWrtUsesTailscaleInitScript(t *testing.T) {
	var commands []string
	withRestartTestHooks(t, "linux", distro.OpenWrt, false, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, restartCommandSpec{name: name, args: args}.String())
		return nil, nil
	})

	if err := restartTailscaled(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/etc/init.d/tailscale restart"}; !reflect.DeepEqual(commands, want) {
		t.Fatalf("restart commands = %v; want %v", commands, want)
	}
}

func TestRestartTailscaledLinuxFallsBackToTailscaleService(t *testing.T) {
	var commands []string
	withRestartTestHooks(t, "linux", distro.Alpine, false, func(name string, args ...string) ([]byte, error) {
		command := restartCommandSpec{name: name, args: args}.String()
		commands = append(commands, command)
		if command == "service tailscale restart" {
			return nil, nil
		}
		return []byte("not found"), errors.New("exit status 1")
	})

	if err := restartTailscaled(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl restart tailscaled.service",
		"service tailscaled restart",
		"service tailscale restart",
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("restart commands = %v; want %v", commands, want)
	}
}

func TestRestartTailscaledContainerGivesManualHint(t *testing.T) {
	withRestartTestHooks(t, "linux", distro.Alpine, true, func(name string, args ...string) ([]byte, error) {
		t.Fatalf("restartCommand(%q, %q) called in container", name, args)
		return nil, nil
	})

	if canRestartTailscaledAutomatically() {
		t.Fatal("canRestartTailscaledAutomatically = true; want false")
	}
	err := restartTailscaled()
	if err == nil || !strings.Contains(err.Error(), "containers") {
		t.Fatalf("restartTailscaled error = %v; want container error", err)
	}
	hint := tailscaledManualRestartHint()
	if !strings.Contains(hint, "docker restart <container>") || !strings.Contains(hint, "Kubernetes") {
		t.Fatalf("manual restart hint = %q; want Docker and Kubernetes guidance", hint)
	}
}

func TestTailscaledManualRestartHintOpenWrt(t *testing.T) {
	withRestartTestHooks(t, "linux", distro.OpenWrt, false, func(name string, args ...string) ([]byte, error) {
		t.Fatalf("restartCommand(%q, %q) called while formatting hint", name, args)
		return nil, nil
	})

	hint := tailscaledManualRestartHint()
	if !strings.Contains(hint, "/etc/init.d/tailscale restart") {
		t.Fatalf("manual restart hint = %q; want OpenWrt init command", hint)
	}
}
