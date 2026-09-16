// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
)

func serverCommand() *ffcli.Command {
	var yes bool
	var noRestart bool
	cmd := &ffcli.Command{
		Name:       "server",
		ShortUsage: "tailscale amnezia-wg server [--yes] [--no-restart] [on|off]",
		ShortHelp:  "Declare this node an HTTP/3 server target (default off)",
		LongHelp:   "One node-wide declaration; no per-peer roles. Default peers retain the existing H3 mesh behavior. Only a non-server node dialing an authenticated declared server uses the chromium-h3 ClientHello profile. Server-to-server, incoming and ordinary mesh connections use standard TLS. This is a Chromium-inspired ClientHello, not a full browser fingerprint clone. The declaration is exchanged automatically inside authenticated H3 CONNECT, without redistributing keys. The daemon restarts automatically unless --no-restart is set, and the server setting does not change transport mode, firewall or listening ports.",
	}
	cmd.FlagSet = flag.NewFlagSet("server", flag.ContinueOnError)
	cmd.FlagSet.BoolVar(&yes, "yes", false, "save the declaration without an interactive confirmation")
	cmd.FlagSet.BoolVar(&noRestart, "no-restart", false, "stage the server declaration without restarting the daemon")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if len(args) == 0 {
			return runAWGStatus(ctx, false, os.Stdout)
		}
		if len(args) != 1 {
			return formatUsageError("tailscale amnezia-wg server [--yes] [--no-restart] [on|off]")
		}
		return stageServerDeclarationWithOptions(ctx, &localClient, args[0], yes, noRestart, os.Stdin, os.Stdout)
	}
	return cmd
}

func stageServerDeclaration(ctx context.Context, client transportClient, value string, yes bool, in io.Reader, out io.Writer) error {
	return stageServerDeclarationWithOptions(ctx, client, value, yes, false, in, out)
}

func stageServerDeclarationWithOptions(ctx context.Context, client transportClient, value string, yes bool, noRestart bool, in io.Reader, out io.Writer) error {
	var enabled bool
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true":
		enabled = true
	case "off", "false":
	default:
		return errors.New("server must be on or off")
	}
	status, err := getTransportStatusForClient(ctx, client)
	if err != nil {
		return err
	}
	if !status.Available {
		return errTransportUnavailable
	}
	if status.Source == "environment" || status.Source == "embedded" {
		return errors.New("transport is externally configured; change its node-wide server option there")
	}
	if status.Server == enabled {
		fmt.Fprintln(out, "Server declaration is already configured; no changes applied.")
		return renderTransportStatus(status, out, false)
	}
	fmt.Fprintf(out, "Stage server=%t for this node. H3 mesh stays enabled in both directions; ports, AWG and peer trust do not change.\n", enabled)
	if !yes {
		confirmed, err := confirmTransportAction(in, out, "Save server declaration? [y/N]: ")
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(out, "No changes applied.")
			return nil
		}
	}
	updated, err := configureTransportForClient(ctx, client, ipn.TransportControlRequest{Action: "server", ExpectedRevision: status.Revision, Server: &enabled})
	if err != nil {
		return err
	}
	if noRestart {
		return renderTransportStatus(updated, out, false)
	}
	if err := applyAndRestartAfterMutation(ctx, false, out, func(ctx context.Context) error {
		return waitForServerState(ctx, client, enabled)
	}); err != nil {
		return err
	}
	status, err = getTransportStatusForClient(ctx, client)
	if err != nil {
		return err
	}
	return renderTransportStatus(status, out, false)
}
