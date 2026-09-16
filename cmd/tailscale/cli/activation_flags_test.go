// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"testing"
)

func TestProfileMutationFlagParsedBeforeExec(t *testing.T) {
	for _, name := range []string{"sync", "reset"} {
		t.Run(name, func(t *testing.T) {
			called := false
			cmd := awgProfileMutationCommand(name, name, func(_ context.Context, args []string, noRestart bool) error {
				called = true
				if !noRestart || len(args) != 0 {
					t.Fatalf("parsed options: noRestart=%v args=%v", noRestart, args)
				}
				return nil
			})
			if err := cmd.ParseAndRun(context.Background(), []string{"--no-restart"}); err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatal("command never reached the configuration handler")
			}
		})
	}
}
