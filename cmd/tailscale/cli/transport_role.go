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

func peerRoleCommand() *ffcli.Command {
	var yes bool
	cmd := &ffcli.Command{
		Name:       "role",
		ShortUsage: "tailscale amnezia-wg peer role [--yes] <peer-public-key> <mesh|client|server>",
		ShortHelp:  "Stage this node's HTTP/3 handshake role for one trusted peer",
		LongHelp:   "Roles describe the LOCAL end of a peer connection, not IP traffic direction. mesh keeps on-demand two-way initiation. client proactively dials; server waits and never reverse-dials. Configure complementary client/server roles on both ends. Changes apply after a later daemon restart in http3-ip mode; they do not open ports, change AWG or enable a browser fingerprint.",
	}
	cmd.FlagSet = flag.NewFlagSet("role", flag.ContinueOnError)
	cmd.FlagSet.BoolVar(&yes, "yes", false, "confirm the next-start per-peer role without an interactive prompt")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if len(args) != 2 {
			return formatUsageError(cmd.ShortUsage)
		}
		return stagePeerRole(ctx, &localClient, args[0], args[1], yes, os.Stdin, os.Stdout)
	}
	return cmd
}

func stagePeerRole(ctx context.Context, client transportClient, peerKey, role string, yes bool, in io.Reader, out io.Writer) error {
	role = strings.ToLower(strings.TrimSpace(role))
	switch role {
	case "mesh", "client", "server":
	default:
		return errors.New("role must be mesh, client or server from this node's perspective")
	}
	status, err := getTransportStatusForClient(ctx, client)
	if err != nil {
		return err
	}
	if !status.Available {
		return errTransportUnavailable
	}
	if status.Source == "environment" || status.Source == "embedded" {
		return errors.New("transport is externally configured; edit the external per-peer policy instead")
	}
	peerKey = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(peerKey)), "nodekey:")
	known := false
	for _, peer := range status.Peers {
		known = known || strings.TrimPrefix(peer.PublicKey, "nodekey:") == peerKey
	}
	if !known {
		return errors.New("role can only be assigned to an already trusted peer")
	}
	if out == nil {
		out = io.Discard
	}
	fmt.Fprintf(out, "Stage local HTTP/3 role %s for peer %s. Both IP directions remain available. No daemon restart or port change will be performed.\n", role, peerKey)
	if role != "mesh" {
		fmt.Fprintln(out, "The other endpoint must use the complementary role (or compatible mesh behavior). This command does not configure it.")
	}
	if !yes {
		ok, err := confirmTransportAction(in, out, "Save this next-start role? [y/N]: ")
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(out, "No changes applied.")
			return nil
		}
	}
	updated, err := configureTransportForClient(ctx, client, ipn.TransportControlRequest{Action: "peer-role", ExpectedRevision: status.Revision, PublicKey: peerKey, ConnectionRole: role})
	if err != nil {
		return err
	}
	return renderTransportStatus(updated, out, false)
}
