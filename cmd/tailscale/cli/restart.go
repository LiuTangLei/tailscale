// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"os/exec"
	"runtime"
)

// restartTailscaled attempts to restart the tailscaled service
func restartTailscaled() error {
	switch runtime.GOOS {
	case "linux":
		// Try systemd first (following clientupdate pattern)
		if _, err := exec.Command("systemctl", "restart", "tailscaled.service").CombinedOutput(); err != nil {
			// Fallback to service command
			if out, err := exec.Command("service", "tailscaled", "restart").CombinedOutput(); err != nil {
				return fmt.Errorf("failed to restart tailscaled: %v\nOutput: %s", err, out)
			}
		}
		return nil
	case "darwin":
		// On macOS, try launchctl
		if out, err := exec.Command("sudo", "launchctl", "kickstart", "-k", "system/com.tailscale.tailscaled").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to restart tailscaled on macOS: %v\nOutput: %s", err, out)
		}
		return nil
	case "windows":
		// On Windows, use net commands (more reliable than sc for restart)
		if out, err := exec.Command("net", "stop", "Tailscale").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to stop tailscaled on Windows: %v\nOutput: %s", err, out)
		}
		if out, err := exec.Command("net", "start", "Tailscale").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to start tailscaled on Windows: %v\nOutput: %s", err, out)
		}
		return nil
	case "freebsd", "openbsd":
		// On BSD systems, use service command (following clientupdate pattern)
		if out, err := exec.Command("service", "tailscaled", "restart").CombinedOutput(); err != nil {
			return fmt.Errorf("failed to restart tailscaled on %s: %v\nOutput: %s", runtime.GOOS, err, out)
		}
		return nil
	default:
		return fmt.Errorf("automatic restart not supported on %s", runtime.GOOS)
	}
}
