// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The tailscale command is the Tailscale command-line client. It interacts
// with the tailscaled node agent.
package main // import "tailscale.com/cmd/tailscale"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"tailscale.com/cmd/tailscale/cli"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && runtime.GOOS == "android" && filepath.IsAbs(args[0]) && strings.Contains(args[0], "tailscale") {
		args = args[1:]
	}
	if name, _ := os.Executable(); strings.HasSuffix(filepath.Base(name), ".cgi") {
		args = []string{"web", "-cgi"}
	}
	if err := cli.Run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
