// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"tailscale.com/ipn"
)

func interactiveTransportIdentity(ctx context.Context, c transportClient, in *bufio.Reader, out io.Writer) error {
	s, err := getTransportStatusForClient(ctx, c)
	if err != nil {
		return err
	}
	if s.Identity == nil {
		fmt.Fprintln(out, "Generate a local TLS key independent of the current IP. Only its PUBLIC identity card will be exported.")
		yes, err := confirmTransportAction(in, out, "Initialize local transport identity? [y/N]: ")
		if err != nil {
			return err
		}
		if !yes {
			return nil
		}
		s, err = configureTransportForClient(ctx, c, ipn.TransportControlRequest{Action: "prepare", ExpectedRevision: s.Revision})
		if err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Exchange this public card over an already trusted channel. Do not send the daemon's private profile file.")
	return renderIdentityJSON(s.Identity, out)
}

func interactiveTransportPeers(ctx context.Context, c transportClient, in *bufio.Reader, out io.Writer) error {
	s, err := getTransportStatusForClient(ctx, c)
	if err != nil {
		return err
	}
	for i, p := range s.Peers {
		fmt.Fprintf(out, "  %d) %s  %s\n", i+1, p.Name, p.PublicKey)
	}
	fmt.Fprintln(out, "Peer action: 1) Import public card  2) Remove a peer  3) List only / return")
	choice, err := readLine(in)
	if err != nil {
		return nil
	}
	req := ipn.TransportControlRequest{ExpectedRevision: s.Revision}
	switch strings.TrimSpace(choice) {
	case "1":
		fmt.Fprintln(out, "Paste a one-line public JSON card, or its local file path (empty cancels):")
		input, err := readLine(in)
		if err != nil || strings.TrimSpace(input) == "" {
			return nil
		}
		peer, err := parseTransportPeerJSON(input)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Trust node %s, TLS SPKI %s. A matching name is NOT proof of identity.\n", peer.PublicKey, peer.SPKISHA256)
		yes, err := confirmTransportAction(in, out, "Confirm this card came over a trusted channel? [y/N]: ")
		if err != nil {
			return err
		}
		if !yes {
			return nil
		}
		req.Action = "add-peer"
		req.Peer = &peer
	case "2":
		fmt.Fprintln(out, "Enter the listed peer number to remove (empty cancels):")
		value, err := readLine(in)
		if err != nil || strings.TrimSpace(value) == "" {
			return nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 1 || n > len(s.Peers) {
			return fmt.Errorf("choose an existing peer number")
		}
		yes, err := confirmTransportAction(in, out, fmt.Sprintf("Stage removal of %s? [y/N]: ", s.Peers[n-1].PublicKey))
		if err != nil {
			return err
		}
		if !yes {
			return nil
		}
		req.Action = "remove-peer"
		req.PublicKey = s.Peers[n-1].PublicKey
	case "", "3":
		return nil
	default:
		return fmt.Errorf("unknown peer action")
	}
	updated, err := configureTransportForClient(ctx, c, req)
	if err != nil {
		return err
	}
	return renderTransportStatus(updated, out, false)
}
