// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"golang.org/x/term"
	"tailscale.com/ipn"
)

var errTransportUnavailable = errors.New("managed transport is unavailable in this daemon; update tailscaled to enable this feature")

type transportClient interface {
	TransportStatus(context.Context) (ipn.TransportControlStatus, error)
	ConfigureTransport(context.Context, ipn.TransportControlRequest) (ipn.TransportControlStatus, error)
}

func runAWGRoot(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return formatUsageError("tailscale awg")
	}
	return runAWGRootMenu(ctx, os.Stdin, os.Stdout, isTTY(os.Stdin), os.Stdout)
}

func runAWGRootMenu(ctx context.Context, in io.Reader, out io.Writer, tty bool, stdOut io.Writer) error {
	if !tty {
		return printAWGHelp(out)
	}
	reader := bufio.NewReader(in)
	for {
		fmt.Fprintln(out, "Tailscale AWG")
		fmt.Fprintln(out, "  1) Status")
		fmt.Fprintln(out, "  2) Native WG / preserve AWG profile")
		fmt.Fprintln(out, "  3) AWG profile actions")
		fmt.Fprintln(out, "  4) QUIC-IP")
		fmt.Fprintln(out, "  5) HTTP/3 experimental")
		fmt.Fprintln(out, "  6) Public identity init/export")
		fmt.Fprintln(out, "  7) Trust peer import/remove")
		fmt.Fprintln(out, "  8) Validate / doctor")
		fmt.Fprintln(out, "  9) Exit")
		fmt.Fprint(out, "Choice [1-9]: ")
		line, err := readLine(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		choice := strings.TrimSpace(strings.ToLower(line))
		switch choice {
		case "1", "status", "s":
			if err := runAWGStatus(ctx, false, stdOut); err != nil {
				fmt.Fprintf(out, "status: %v\n", err)
			}
		case "2", "native", "wg", "standard":
			fmt.Fprintln(out, "Native mode preserves the AWG profile until you explicitly reset it.")
			if err := runAWGTransportMode(ctx, "native", false, reader, stdOut); err != nil {
				fmt.Fprintf(out, "native: %v\n", err)
			}
		case "3", "awg", "profile":
			// The legacy profile generator uses Scanner; keep it one-shot so
			// its read-ahead cannot consume a subsequent root-menu command.
			fmt.Fprintln(out, "Generate an AWG profile here; use 'awg sync', 'get', or 'reset' for existing profile operations.")
			return runInteractiveAWGProfile(ctx, reader, stdOut)
		case "4", "quic-ip", "quic":
			if err := runAWGTransportMode(ctx, "quic-ip", false, reader, stdOut); err != nil {
				fmt.Fprintf(out, "quic-ip: %v\n", err)
			}
		case "5", "http3-ip", "http3":
			if err := runAWGTransportMode(ctx, "http3-ip", false, reader, stdOut); err != nil {
				fmt.Fprintf(out, "http3-ip: %v\n", err)
			}
		case "6", "identity":
			if err := interactiveTransportIdentity(ctx, &localClient, reader, stdOut); err != nil {
				fmt.Fprintf(out, "identity: %v\n", err)
			}
		case "7", "peer", "import", "trust-peer", "trust":
			if err := interactiveTransportPeers(ctx, &localClient, reader, stdOut); err != nil {
				fmt.Fprintf(out, "peer: %v\n", err)
			}
		case "8", "validate", "doctor":
			if err := runAWGDoctor(ctx, stdOut); err != nil {
				fmt.Fprintf(out, "doctor: %v\n", err)
			}
		case "", "9", "exit", "q", "quit":
			return nil
		default:
			fmt.Fprintln(out, "Invalid choice.")
		}
	}
}

func printAWGHelp(out io.Writer) error {
	_, err := fmt.Fprintln(out, "Usage: tailscale awg [status|transport|identity|peer|doctor|set|get|sync|reset|validate]")
	return err
}

func readLine(r *bufio.Reader) (string, error) {
	if r == nil {
		return "", io.EOF
	}
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if errors.Is(err, io.EOF) && line == "" {
		return "", io.EOF
	}
	return line, nil
}

func isTTY(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok || f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func transportModeIsValid(mode string) bool {
	switch strings.ToLower(mode) {
	case "native", "quic-ip", "http3-ip":
		return true
	default:
		return false
	}
}

func transportModeUsesQUIC(mode string) bool {
	switch strings.ToLower(mode) {
	case "quic-ip", "http3-ip":
		return true
	default:
		return false
	}
}

func getTransportStatus(ctx context.Context) (ipn.TransportControlStatus, error) {
	return getTransportStatusForClient(ctx, &localClient)
}

func getTransportStatusForClient(ctx context.Context, client transportClient) (ipn.TransportControlStatus, error) {
	if client == nil {
		return ipn.TransportControlStatus{}, errTransportUnavailable
	}
	status, err := client.TransportStatus(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "405") || strings.Contains(err.Error(), "method not allowed") || strings.Contains(err.Error(), "not found") {
			return ipn.TransportControlStatus{}, errTransportUnavailable
		}
		return ipn.TransportControlStatus{}, err
	}
	return status, nil
}

func configureTransport(ctx context.Context, req ipn.TransportControlRequest) (ipn.TransportControlStatus, error) {
	return configureTransportForClient(ctx, &localClient, req)
}

func configureTransportForClient(ctx context.Context, client transportClient, req ipn.TransportControlRequest) (ipn.TransportControlStatus, error) {
	if client == nil {
		return ipn.TransportControlStatus{}, errTransportUnavailable
	}
	status, err := client.ConfigureTransport(ctx, req)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "405") || strings.Contains(err.Error(), "method not allowed") || strings.Contains(err.Error(), "not found") {
			return ipn.TransportControlStatus{}, errTransportUnavailable
		}
		return ipn.TransportControlStatus{}, err
	}
	return status, nil
}

func runAWGStatus(ctx context.Context, jsonOut bool, out io.Writer) error {
	status, err := getTransportStatus(ctx)
	if err != nil {
		return err
	}
	return renderTransportStatus(status, out, jsonOut)
}

func renderTransportStatus(status ipn.TransportControlStatus, out io.Writer, jsonOut bool) error {
	if out == nil {
		out = io.Discard
	}
	if jsonOut {
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		return enc.Encode(status)
	}
	if status.ActiveMode == "" {
		status.ActiveMode = "native"
	}
	if status.DesiredMode == "" {
		status.DesiredMode = status.ActiveMode
	}
	if status.Source == "" {
		status.Source = "default"
	}
	fmt.Fprintf(out, "Transport status\n")
	fmt.Fprintf(out, "  Active mode: %s\n", status.ActiveMode)
	fmt.Fprintf(out, "  Desired mode: %s\n", status.DesiredMode)
	if status.PendingRestart {
		fmt.Fprintln(out, "  Pending restart: yes")
		if status.ActiveMode != status.DesiredMode {
			fmt.Fprintf(out, "  Restart required to activate %s.\n", status.DesiredMode)
		}
	} else {
		fmt.Fprintln(out, "  Pending restart: no")
	}
	if status.Source != "" {
		fmt.Fprintf(out, "  Source: %s\n", status.Source)
	}
	if status.LocalPublicKey != "" {
		fmt.Fprintf(out, "  Local public key: %s\n", status.LocalPublicKey)
	}
	if status.Identity != nil {
		fmt.Fprintf(out, "  Identity: %s (%s)\n", status.Identity.Name, status.Identity.PublicKey)
	}
	fmt.Fprintf(out, "  Trusted peers: %d\n", len(status.Peers))
	if !status.MixedPeerSupport {
		fmt.Fprintln(out, "  Concurrent native/QUIC peers: not supported by this build")
	}
	if len(status.UnconfiguredPeers) != 0 {
		fmt.Fprintf(out, "  Routable peers without QUIC identity: %d (QUIC activation is blocked)\n", len(status.UnconfiguredPeers))
	}
	if status.AWGConfigured {
		fmt.Fprintln(out, "  AWG configured: yes")
		if transportModeUsesQUIC(status.DesiredMode) || transportModeUsesQUIC(status.ActiveMode) {
			fmt.Fprintln(out, "  Warning: QUIC transport does not use AWG. Reset AWG explicitly before using quic-ip or http3-ip.")
		}
	} else {
		fmt.Fprintln(out, "  AWG configured: no")
	}
	for _, warn := range status.Warnings {
		fmt.Fprintf(out, "  Warning: %s\n", warn)
	}
	if status.Revision != "" {
		fmt.Fprintf(out, "  Revision: %s\n", status.Revision)
	}
	return nil
}

func runAWGTransport(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return formatUsageError("tailscale awg transport [native|quic-ip|http3-ip]")
	}
	return runAWGTransportMode(ctx, args[0], false, os.Stdin, os.Stdout)
}

func transportModeRequest(status ipn.TransportControlStatus, mode string) ipn.TransportControlRequest {
	return ipn.TransportControlRequest{Action: "mode", ExpectedRevision: status.Revision, Mode: mode}
}

func runAWGTransportMode(ctx context.Context, mode string, yes bool, in io.Reader, out io.Writer) error {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if !transportModeIsValid(mode) {
		return fmt.Errorf("invalid mode %q: supported values are native, quic-ip, http3-ip", mode)
	}
	return stageTransportMode(ctx, &localClient, mode, yes, in, out)
}

func stageTransportMode(ctx context.Context, client transportClient, mode string, yes bool, in io.Reader, out io.Writer) error {
	if !transportModeIsValid(mode) {
		return errors.New("invalid transport mode")
	}
	status, err := getTransportStatusForClient(ctx, client)
	if err != nil {
		return err
	}
	if !status.Available {
		return errTransportUnavailable
	}
	if status.Source == "environment" || status.Source == "embedded" {
		return errors.New("transport is externally configured; remove that override before staging a managed mode")
	}
	if transportModeUsesQUIC(mode) && status.AWGConfigured {
		return errors.New("Reset AWG explicitly before staging QUIC-IP/HTTP3-IP; existing AWG links may be interrupted")
	}
	if mode == "http3-ip" {
		fmt.Fprintln(out, "HTTP/3 is experimental, not a Chrome fingerprint clone; performance depends on the path.")
	}
	fmt.Fprintf(out, "Active: %s; stage %s for the next daemon start. This command will NOT restart the daemon.\n", status.ActiveMode, mode)
	if !yes {
		confirmed, err := confirmTransportAction(in, out, fmt.Sprintf("Switch transport mode to %s? [y/N]: ", mode))
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(out, "No changes applied.")
			return nil
		}
	}
	req := transportModeRequest(status, mode)
	updated, err := configureTransportForClient(ctx, client, req)
	if err != nil {
		return err
	}
	return renderTransportStatus(updated, out, false)
}

func confirmTransportAction(in io.Reader, out io.Writer, prompt string) (bool, error) {
	if in == nil {
		return false, nil
	}
	reader, ok := in.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(in)
	}
	for {
		fmt.Fprint(out, prompt)
		line, err := readLine(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "n", "no", "q", "quit", "cancel":
			return false, nil
		case "y", "yes":
			return true, nil
		default:
			fmt.Fprintln(out, "Enter y to confirm or n to cancel.")
		}
	}
}

func runAWGIdentity(ctx context.Context, init bool, out io.Writer) error {
	status, err := getTransportStatus(ctx)
	if err != nil {
		return err
	}
	if init {
		status, err = configureTransport(ctx, ipn.TransportControlRequest{Action: "prepare", ExpectedRevision: status.Revision})
		if err != nil {
			return err
		}
	}
	if status.Identity == nil {
		return errors.New("no public identity has been initialized")
	}
	return renderIdentityJSON(status.Identity, out)
}

func renderIdentityJSON(peer *ipn.TransportPeer, out io.Writer) error {
	if peer == nil {
		return errors.New("no public identity has been initialized")
	}
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	return enc.Encode(peer)
}

func runAWGDoctor(ctx context.Context, out io.Writer) error {
	status, err := configureTransport(ctx, ipn.TransportControlRequest{Action: "validate"})
	if err != nil {
		return err
	}
	if status.AWGConfigured && transportModeUsesQUIC(status.ActiveMode) {
		fmt.Fprintln(out, "Warning: active QUIC transport does not use AWG. Reset the AWG profile to return to WG/native operation.")
	}
	for _, warn := range status.Warnings {
		fmt.Fprintf(out, "Warning: %s\n", warn)
	}
	return renderTransportStatus(status, out, false)
}

func renderLocalAWGStatus(ctx context.Context, out io.Writer) error {
	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}
	if prefs.AmneziaWG.IsZero() {
		fmt.Fprintln(out, "Native mode: AWG profile is not configured; this is standard WireGuard behavior.")
	} else {
		fmt.Fprintln(out, "Native mode is active while AWG remains configured. Use 'tailscale awg reset' to return to standard WireGuard explicitly.")
	}
	printAmneziaWGConfig(prefs.AmneziaWG)
	return nil
}

func runAWGPeerList(ctx context.Context, out io.Writer) error {
	status, err := getTransportStatus(ctx)
	if err != nil {
		return err
	}
	if len(status.Peers) == 0 {
		fmt.Fprintln(out, "No trusted peers configured.")
		return nil
	}
	for i, peer := range status.Peers {
		fmt.Fprintf(out, "[%d] %s (%s)\n", i+1, peer.Name, peer.PublicKey)
	}
	return nil
}

func runInteractiveAWGProfile(ctx context.Context, in io.Reader, out io.Writer) error {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	curPrefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(in)
	config, err := promptAWGProfile(scanner, out, rand.Reader, curPrefs.AmneziaWG)
	if err != nil {
		return err
	}
	if err := applyAmneziaWGConfig(ctx, config); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s configuration applied.\n", amneziaConfigVersion(config))
	fmt.Fprintln(out, "The AWG preferences were updated; the daemon was not restarted.")
	return nil
}

func readTransportPeerJSON(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("peer JSON is empty")
	}
	var data []byte
	if fi, err := os.Stat(trimmed); err == nil {
		if !fi.Mode().IsRegular() || fi.Size() > 16<<10 {
			return nil, errors.New("peer card must be a regular file no larger than 16 KiB")
		}
		f, err := os.Open(trimmed)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		data, err = io.ReadAll(io.LimitReader(f, (16<<10)+1))
		if err != nil {
			return nil, err
		}
	} else {
		data = []byte(trimmed)
	}
	if len(data) > 16<<10 {
		return nil, errors.New("peer JSON exceeds 16 KiB limit")
	}
	return data, nil
}

func parseTransportPeerJSON(input string) (ipn.TransportPeer, error) {
	data, err := readTransportPeerJSON(input)
	if err != nil {
		return ipn.TransportPeer{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	tok, err := dec.Token()
	if err != nil {
		return ipn.TransportPeer{}, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return ipn.TransportPeer{}, errors.New("peer JSON must be an object")
	}
	var peer ipn.TransportPeer
	seen := make(map[string]bool)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return ipn.TransportPeer{}, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return ipn.TransportPeer{}, errors.New("peer JSON contains a non-string field")
		}
		if seen[key] {
			return ipn.TransportPeer{}, fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		switch key {
		case "name":
			if err := dec.Decode(&peer.Name); err != nil {
				return ipn.TransportPeer{}, err
			}
		case "public_key":
			if err := dec.Decode(&peer.PublicKey); err != nil {
				return ipn.TransportPeer{}, err
			}
		case "spki_sha256":
			if err := dec.Decode(&peer.SPKISHA256); err != nil {
				return ipn.TransportPeer{}, err
			}
		case "http3_url":
			if err := dec.Decode(&peer.HTTP3URL); err != nil {
				return ipn.TransportPeer{}, err
			}
		default:
			return ipn.TransportPeer{}, fmt.Errorf("unknown peer field %q", key)
		}
	}
	if _, err := dec.Token(); err != nil {
		return ipn.TransportPeer{}, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ipn.TransportPeer{}, errors.New("expected exactly one public identity card")
	}
	if peer.PublicKey == "" || peer.SPKISHA256 == "" {
		return ipn.TransportPeer{}, errors.New("peer JSON requires public_key and spki_sha256")
	}
	return peer, nil
}

func runAWGPeerAdd(ctx context.Context, input string, filePath string, out io.Writer) error {
	status, err := getTransportStatus(ctx)
	if err != nil {
		return err
	}
	data := input
	if filePath != "" {
		data = filePath
	}
	peer, err := parseTransportPeerJSON(data)
	if err != nil {
		return err
	}
	if !yesOrPrompt(os.Stdin, out, "Add trusted peer %s? [y/N]: ", peer.PublicKey) {
		fmt.Fprintln(out, "No changes applied.")
		return nil
	}
	req := ipn.TransportControlRequest{Action: "add-peer", ExpectedRevision: status.Revision, Peer: &peer}
	updated, err := configureTransport(ctx, req)
	if err != nil {
		return err
	}
	return renderTransportStatus(updated, out, false)
}

func yesOrPrompt(in io.Reader, out io.Writer, format string, args ...any) bool {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	reader, ok := in.(*bufio.Reader)
	if !ok {
		reader = bufio.NewReader(in)
	}
	for {
		fmt.Fprintf(out, format, args...)
		line, err := readLine(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false
			}
			fmt.Fprintf(out, "prompt error: %v\n", err)
			return false
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "n", "no", "q", "quit", "cancel":
			return false
		case "y", "yes":
			return true
		default:
			fmt.Fprintln(out, "Enter y to confirm or n to cancel.")
		}
	}
}

func runAWGPeerRemove(ctx context.Context, publicKey string, out io.Writer) error {
	status, err := getTransportStatus(ctx)
	if err != nil {
		return err
	}
	if publicKey == "" {
		return errors.New("peer public key is required")
	}
	if !yesOrPrompt(os.Stdin, out, "Remove peer %s? [y/N]: ", publicKey) {
		fmt.Fprintln(out, "No changes applied.")
		return nil
	}
	req := ipn.TransportControlRequest{Action: "remove-peer", ExpectedRevision: status.Revision, PublicKey: publicKey}
	updated, err := configureTransport(ctx, req)
	if err != nil {
		return err
	}
	return renderTransportStatus(updated, out, false)
}

func runAWGIdentityInit(ctx context.Context, out io.Writer) error {
	if out == nil {
		out = os.Stdout
	}
	return runAWGIdentity(ctx, true, out)
}

func transportStatusCommand() *ffcli.Command {
	var jsonOut bool
	cmd := &ffcli.Command{
		Name:       "status",
		ShortUsage: "tailscale amnezia-wg status [--json]",
		ShortHelp:  "Render the current transport status",
		LongHelp:   "Report the active transport mode, desired mode, restart state, source, and identity metadata.",
	}
	cmd.FlagSet = flag.NewFlagSet("status", flag.ContinueOnError)
	cmd.FlagSet.BoolVar(&jsonOut, "json", false, "emit status as JSON")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if len(args) != 0 {
			return formatUsageError("tailscale amnezia-wg status [--json]")
		}
		return runAWGStatus(ctx, jsonOut, os.Stdout)
	}
	return cmd
}

func transportCommand() *ffcli.Command {
	var yes bool
	cmd := &ffcli.Command{
		Name:       "transport",
		ShortUsage: "tailscale amnezia-wg transport [native|quic-ip|http3-ip]",
		ShortHelp:  "Stage a transport mode change",
		LongHelp:   "Switch between native WG/AWG, quic-ip, and http3-ip. Changes are staged and require a later daemon restart.",
	}
	cmd.FlagSet = flag.NewFlagSet("transport", flag.ContinueOnError)
	cmd.FlagSet.BoolVar(&yes, "yes", false, "skip confirmation and stage the next-start mode (does not restart)")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if len(args) != 1 {
			return formatUsageError("tailscale amnezia-wg transport [native|quic-ip|http3-ip]")
		}
		return runAWGTransportMode(ctx, args[0], yes, os.Stdin, os.Stdout)
	}
	return cmd
}

func identityCommand() *ffcli.Command {
	var init bool
	var jsonOut bool
	cmd := &ffcli.Command{
		Name:       "identity",
		ShortUsage: "tailscale amnezia-wg identity [--init] [--json]",
		ShortHelp:  "Export or initialize the local public identity card",
		LongHelp:   "Print the public identity card or initialize it with the daemon. Private keys are never exposed.",
	}
	cmd.FlagSet = flag.NewFlagSet("identity", flag.ContinueOnError)
	cmd.FlagSet.BoolVar(&init, "init", false, "initialize the daemon-side public identity and emit the resulting public card")
	cmd.FlagSet.BoolVar(&jsonOut, "json", false, "emit the public identity as JSON")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if len(args) != 0 {
			return formatUsageError("tailscale amnezia-wg identity [--init] [--json]")
		}
		if init {
			return runAWGIdentity(ctx, true, os.Stdout)
		}
		if jsonOut {
			return runAWGIdentity(ctx, false, os.Stdout)
		}
		return runAWGIdentity(ctx, false, os.Stdout)
	}
	return cmd
}

func peerCommand() *ffcli.Command {
	return &ffcli.Command{
		Name:       "peer",
		ShortUsage: "tailscale amnezia-wg peer [add|remove|list]",
		ShortHelp:  "Manage trusted transport peers",
		Subcommands: []*ffcli.Command{
			peerAddCommand(),
			peerRemoveCommand(),
			peerListCommand(),
		},
	}
}

func peerAddCommand() *ffcli.Command {
	var yes bool
	var file string
	cmd := &ffcli.Command{
		Name:       "add",
		ShortUsage: "tailscale amnezia-wg peer add <public-json-or-file>",
		ShortHelp:  "Trust a peer by JSON or a file path",
	}
	cmd.FlagSet = flag.NewFlagSet("add", flag.ContinueOnError)
	cmd.FlagSet.BoolVar(&yes, "yes", false, "skip confirmation before adding the peer")
	cmd.FlagSet.StringVar(&file, "file", "", "path to a JSON transport peer file")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if len(args) > 1 || (len(args) == 0 && file == "") || (len(args) != 0 && file != "") {
			return formatUsageError("tailscale amnezia-wg peer add [--file path|<public-json>]")
		}
		input := ""
		if len(args) == 1 {
			input = args[0]
		}
		if file != "" {
			input = file
		}
		if yes {
			status, err := getTransportStatus(ctx)
			if err != nil {
				return err
			}
			peer, err := parseTransportPeerJSON(input)
			if err != nil {
				return err
			}
			req := ipn.TransportControlRequest{Action: "add-peer", ExpectedRevision: status.Revision, Peer: &peer}
			updated, err := configureTransport(ctx, req)
			if err != nil {
				return err
			}
			return renderTransportStatus(updated, os.Stdout, false)
		}
		return runAWGPeerAdd(ctx, input, file, os.Stdout)
	}
	return cmd
}

func peerRemoveCommand() *ffcli.Command {
	var yes bool
	cmd := &ffcli.Command{
		Name:       "remove",
		ShortUsage: "tailscale amnezia-wg peer remove <node-public-key>",
		ShortHelp:  "Remove a trusted peer",
	}
	cmd.FlagSet = flag.NewFlagSet("remove", flag.ContinueOnError)
	cmd.FlagSet.BoolVar(&yes, "yes", false, "skip confirmation before removing the peer")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if len(args) != 1 {
			return formatUsageError("tailscale amnezia-wg peer remove <node-public-key>")
		}
		if yes {
			status, err := getTransportStatus(ctx)
			if err != nil {
				return err
			}
			req := ipn.TransportControlRequest{Action: "remove-peer", ExpectedRevision: status.Revision, PublicKey: args[0]}
			updated, err := configureTransport(ctx, req)
			if err != nil {
				return err
			}
			return renderTransportStatus(updated, os.Stdout, false)
		}
		return runAWGPeerRemove(ctx, args[0], os.Stdout)
	}
	return cmd
}

func peerListCommand() *ffcli.Command {
	cmd := &ffcli.Command{
		Name:       "list",
		ShortUsage: "tailscale amnezia-wg peer list",
		ShortHelp:  "List trusted peers",
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 0 {
				return formatUsageError("tailscale amnezia-wg peer list")
			}
			return runAWGPeerList(ctx, os.Stdout)
		},
	}
	return cmd
}

func doctorCommand() *ffcli.Command {
	cmd := &ffcli.Command{
		Name:       "doctor",
		ShortUsage: "tailscale amnezia-wg doctor",
		ShortHelp:  "Run transport validation diagnostics",
		Exec: func(ctx context.Context, args []string) error {
			if len(args) != 0 {
				return formatUsageError("tailscale amnezia-wg doctor")
			}
			return runAWGDoctor(ctx, os.Stdout)
		},
	}
	return cmd
}
