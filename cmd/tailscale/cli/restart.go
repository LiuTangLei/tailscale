// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"tailscale.com/hostinfo"
	"tailscale.com/version/distro"
)

type restartCommandSpec struct {
	name string
	args []string
}

func (command restartCommandSpec) String() string {
	return strings.Join(append([]string{command.name}, command.args...), " ")
}

var (
	restartGOOS        = func() string { return runtime.GOOS }
	restartDistro      = distro.Get
	restartInContainer = defaultRestartInContainer
	restartCommand     = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
)

// restartTailscaled attempts to restart the tailscaled service.
func restartTailscaled() error {
	switch restartGOOS() {
	case "linux":
		if restartInContainer() {
			return errors.New("automatic restart is not supported inside containers")
		}
		if restartDistro() == distro.OpenWrt {
			return runRestartCommands("OpenWrt", []restartCommandSpec{
				{name: "/etc/init.d/tailscale", args: []string{"restart"}},
				{name: "service", args: []string{"tailscale", "restart"}},
			})
		}
		return runRestartCommands("Linux", []restartCommandSpec{
			{name: "systemctl", args: []string{"restart", "tailscaled.service"}},
			{name: "service", args: []string{"tailscaled", "restart"}},
			{name: "service", args: []string{"tailscale", "restart"}},
			{name: "/etc/init.d/tailscale", args: []string{"restart"}},
		})
	case "darwin":
		// On macOS, try launchctl
		if out, err := restartCommand("sudo", "launchctl", "kickstart", "-k", "system/com.tailscale.tailscaled"); err != nil {
			return fmt.Errorf("failed to restart tailscaled on macOS: %v\nOutput: %s", err, out)
		}
		return nil
	case "windows":
		// On Windows, use net commands (more reliable than sc for restart)
		if out, err := restartCommand("net", "stop", "Tailscale"); err != nil {
			return fmt.Errorf("failed to stop tailscaled on Windows: %v\nOutput: %s", err, out)
		}
		if out, err := restartCommand("net", "start", "Tailscale"); err != nil {
			return fmt.Errorf("failed to start tailscaled on Windows: %v\nOutput: %s", err, out)
		}
		return nil
	case "freebsd", "openbsd":
		// On BSD systems, use service command (following clientupdate pattern)
		return runRestartCommands(restartGOOS(), []restartCommandSpec{
			{name: "service", args: []string{"tailscaled", "restart"}},
		})
	default:
		return fmt.Errorf("automatic restart not supported on %s", restartGOOS())
	}
}

func runRestartCommands(platform string, commands []restartCommandSpec) error {
	var failures []string
	for _, command := range commands {
		output, err := restartCommand(command.name, command.args...)
		if err == nil {
			return nil
		}
		trimmedOutput := strings.TrimSpace(string(output))
		if trimmedOutput == "" {
			failures = append(failures, fmt.Sprintf("%s: %v", command, err))
			continue
		}
		failures = append(failures, fmt.Sprintf("%s: %v: %s", command, err, trimmedOutput))
	}
	return fmt.Errorf("no supported restart method succeeded on %s:\n%s", platform, strings.Join(failures, "\n"))
}

func canRestartTailscaledAutomatically() bool {
	return !(restartGOOS() == "linux" && restartInContainer())
}

func tailscaledManualRestartHint() string {
	if restartGOOS() == "linux" {
		if restartInContainer() {
			return "Please restart the container from the host for changes to take effect (Docker: docker restart <container>; Kubernetes: restart/delete the pod)."
		}
		if restartDistro() == distro.OpenWrt {
			return "Please run /etc/init.d/tailscale restart for changes to take effect."
		}
	}
	return "Please restart tailscaled manually for changes to take effect."
}

func defaultRestartInContainer() bool {
	if restartGOOS() != "linux" {
		return false
	}
	info := hostinfo.New()
	if info.Package == "container" || info.Container.EqualBool(true) {
		return true
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	return false
}
