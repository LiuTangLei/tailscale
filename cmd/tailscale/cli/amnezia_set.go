// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
)

var errAWGSetupCancelled = errors.New("AmneziaWG setup cancelled")
var errQUICSetupSelected = errors.New("QUIC selected")

type awgProfileVersion uint8

const (
	awgProfileV2   awgProfileVersion = 2
	awgProfileV3   awgProfileVersion = 3
	awgProfileQUIC awgProfileVersion = 4
)

func (v awgProfileVersion) String() string {
	switch v {
	case awgProfileV2:
		return "AWG v2"
	case awgProfileV3:
		return "AWG v3"
	default:
		return fmt.Sprintf("AWG v%d", v)
	}
}

func awgSetCommand() *ffcli.Command {
	var yes bool
	var noRestart bool
	cmd := &ffcli.Command{
		Name:       "set",
		ShortUsage: "tailscale amnezia-wg set [--yes] [--no-restart] [quic|json-string]",
		ShortHelp:  "Configure AWG v3, AWG v2, or QUIC",
		LongHelp:   "Choose AWG v3, AWG v2, or QUIC interactively. QUIC includes the built-in obfuscation and automatically clears the saved AWG profile after confirmation. Use 'set --yes quic' for noninteractive selection, or pass an AWG JSON object directly. The daemon restarts automatically unless --no-restart is set.",
		FlagSet:    flag.NewFlagSet("set", flag.ContinueOnError),
	}
	cmd.FlagSet.BoolVar(&yes, "yes", false, "confirm the selection and restart the daemon to activate it")
	cmd.FlagSet.BoolVar(&noRestart, "no-restart", false, "stage the change without restarting the local daemon")
	cmd.Exec = func(ctx context.Context, args []string) error {
		if yes {
			_, err := configureAWGSetWithOptions(ctx, &localClient, args, true, noRestart, bufio.NewScanner(os.Stdin), os.Stdout)
			return err
		}
		return runAmneziaWGSetWithOptions(ctx, args, noRestart)
	}
	return cmd
}

type awgSetupClient interface {
	transportClient
	GetPrefs(context.Context) (*ipn.Prefs, error)
	EditPrefs(context.Context, *ipn.MaskedPrefs) (*ipn.Prefs, error)
}

func runAmneziaWGSet(ctx context.Context, args []string) error {
	return runAmneziaWGSetWithOptions(ctx, args, false)
}

func runAmneziaWGSetWithOptions(ctx context.Context, args []string, noRestart bool) error {
	changed, err := configureAWGSetWithOptions(ctx, &localClient, args, false, noRestart, bufio.NewScanner(os.Stdin), os.Stdout)
	if err != nil || !changed {
		return err
	}
	return nil
}

func configureAWGSet(ctx context.Context, client awgSetupClient, args []string, yes bool, scanner *bufio.Scanner, out io.Writer) (bool, error) {
	return configureAWGSetWithOptions(ctx, client, args, yes, false, scanner, out)
}

func configureAWGSetWithOptions(ctx context.Context, client awgSetupClient, args []string, yes bool, noRestart bool, scanner *bufio.Scanner, out io.Writer) (bool, error) {
	selectQUIC := func() (bool, error) {
		return stageTransportSelectionWithOptions(ctx, client, "quic", yes, noRestart, out, func(prompt string) (bool, error) {
			for {
				fmt.Fprint(out, prompt)
				if !scanner.Scan() {
					return false, scanner.Err()
				}
				switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
				case "y", "yes":
					return true, nil
				case "", "n", "no", "q", "quit", "cancel":
					return false, nil
				default:
					fmt.Fprintln(out, "Enter y to apply or n to cancel.")
				}
			}
		})
	}
	var config ipn.AmneziaWGPrefs
	switch len(args) {
	case 1:
		if canonicalTransportMode(args[0]) == "http3-ip" {
			return selectQUIC()
		}
		var err error
		config, err = parseConfigFromArgs(ctx, args)
		if err != nil {
			return false, err
		}
	case 0:
		prefs, err := client.GetPrefs(ctx)
		if err != nil {
			return false, err
		}
		config, err = promptAWGProfile(scanner, out, cryptorand.Reader, prefs.AmneziaWG)
		if errors.Is(err, errQUICSetupSelected) {
			return selectQUIC()
		}
		if errors.Is(err, errAWGSetupCancelled) {
			fmt.Fprintln(out, "No changes applied.")
			return false, nil
		}
		if err != nil {
			return false, err
		}
	default:
		return false, formatUsageError("tailscale awg set [--yes] [--no-restart] [quic|json-string]")
	}
	if !noRestart {
		if err := ensureSafeLocalRestart(); err != nil {
			return false, err
		}
	}
	pending, err := applyAWGForClient(ctx, client, config)
	if err != nil {
		return false, err
	}
	if pending {
		fmt.Fprintf(out, "%s saved. Native WG/AWG will activate after one daemon restart; the running QUIC connection is unchanged.\n", amneziaConfigVersion(config))
	} else {
		fmt.Fprintf(out, "%s configuration saved.\n", amneziaConfigVersion(config))
	}
	if err := applyAndRestartAfterMutation(ctx, noRestart, out, func(ctx context.Context) error {
		return waitForAWGConfig(ctx, client, config)
	}); err != nil {
		return false, err
	}
	if !noRestart {
		fmt.Fprintf(out, "%s is active.\n", amneziaConfigVersion(config))
	}
	return true, nil
}

// JSON remains the advanced AWG path and retains historical field aliases.
func parseConfigFromArgs(_ context.Context, args []string) (ipn.AmneziaWGPrefs, error) {
	var config ipn.AmneziaWGPrefs
	if len(args) != 1 {
		return config, formatUsageError("tailscale awg set [--yes] [quic|json-string]")
	}
	if err := json.Unmarshal([]byte(args[0]), &config); err != nil {
		return config, fmt.Errorf("invalid JSON or mode: use 'quic' or an AWG JSON object: %w", err)
	}
	return config, nil
}

func promptAWGProfile(scanner *bufio.Scanner, out io.Writer, rng io.Reader, current ipn.AmneziaWGPrefs) (ipn.AmneziaWGPrefs, error) {
	fmt.Fprintf(out, "Tailscale AWG / QUIC setup\nCurrent profile: %s\n\n", amneziaConfigVersion(current))
	fmt.Fprintln(out, "Select a mode:")
	fmt.Fprintln(out, "  1) AWG v3 (recommended, default)")
	fmt.Fprintln(out, "  2) AWG v2 (legacy compatibility)")
	fmt.Fprintln(out, "  3) QUIC (built-in obfuscation; clears AWG settings)")
	fmt.Fprintln(out, "  q) Cancel")
	fmt.Fprintln(out, "For custom fields, pass a JSON object directly to 'tailscale awg set'.")

	version, err := promptAWGProfileVersion(scanner, out)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	if version == awgProfileQUIC {
		return ipn.AmneziaWGPrefs{}, errQUICSetupSelected
	}
	config, err := generateAWGProfile(version, rng)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, fmt.Errorf("generate %s profile: %w", version, err)
	}

	if err := printGeneratedAWGProfile(out, config); err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	confirmed, err := promptAWGConfirmation(scanner, out)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	if !confirmed {
		return ipn.AmneziaWGPrefs{}, errAWGSetupCancelled
	}
	return config, nil
}

func promptAWGProfileVersion(scanner *bufio.Scanner, out io.Writer) (awgProfileVersion, error) {
	for {
		fmt.Fprint(out, "Profile [1]: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return 0, err
			}
			return 0, errors.New("interactive input closed before a profile was selected")
		}
		switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
		case "", "1", "v3", "awg3", "awg-v3":
			return awgProfileV3, nil
		case "2", "v2", "awg2", "awg-v2":
			return awgProfileV2, nil
		case "3", "quic", "http3-ip", "http3", "h3":
			return awgProfileQUIC, nil
		case "q", "quit", "cancel":
			return 0, errAWGSetupCancelled
		default:
			fmt.Fprintln(out, "Enter 1 for AWG v3, 2 for AWG v2, 3 for QUIC, or q to cancel.")
		}
	}
}

func promptAWGConfirmation(scanner *bufio.Scanner, out io.Writer) (bool, error) {
	for {
		fmt.Fprint(out, "Apply this profile now? [Y/n]: ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return false, err
			}
			return false, errors.New("interactive input closed before confirmation")
		}
		switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
		case "", "y", "yes":
			return true, nil
		case "n", "no", "q", "quit", "cancel":
			return false, nil
		default:
			fmt.Fprintln(out, "Enter y to apply or n to cancel.")
		}
	}
}

func printGeneratedAWGProfile(out io.Writer, config ipn.AmneziaWGPrefs) error {
	encoded, err := formatConfigAsJSON(config)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "\nGenerated %s profile:\n", amneziaConfigVersion(config))
	fmt.Fprintf(out, "  Junk: JC=%d, JMin=%d, JMax=%d\n", config.JC, config.JMin, config.JMax)
	fmt.Fprintf(out, "  Prefixes: S1=%d, S2=%d, S3=%d, S4=%d\n", config.S1, config.S2, config.S3, config.S4)
	fmt.Fprintf(out, "  Headers: H1=%s, H2=%s, H3=%s, H4=%s\n", config.H1, config.H2, config.H3, config.H4)
	if hasV3Config(config) {
		keyPreview := config.HeaderProtectionKey
		if len(keyPreview) > 12 {
			keyPreview = keyPreview[:12] + "..."
		}
		if keyPreview == "" {
			keyPreview = "disabled"
		}
		fmt.Fprintf(out, "  Header protection key: %s\n", keyPreview)
		fmt.Fprintf(out, "  v3 padding/timing: padding=%s, rekey=%s, timeout=%s, reject=%s, keepalive=%s, attempts=%s\n",
			config.ContentPaddingAddition,
			config.RekeyAfterTime,
			config.RekeyTimeout,
			config.RejectAfterTime,
			config.KeepaliveTimeout,
			config.MaxHandshakeAttempts,
		)
	} else {
		fmt.Fprintln(out, "  AWG v3-only fields: disabled")
	}
	fmt.Fprintln(out, "\nCopy this exact JSON to every peer that must communicate with this node:")
	fmt.Fprintln(out, encoded)
	fmt.Fprintln(out, "Peers using a different AWG profile may lose connectivity.")
	return nil
}

func generateAWGProfile(version awgProfileVersion, rng io.Reader) (ipn.AmneziaWGPrefs, error) {
	if version != awgProfileV2 && version != awgProfileV3 {
		return ipn.AmneziaWGPrefs{}, fmt.Errorf("unsupported profile version %d", version)
	}
	if rng == nil {
		return ipn.AmneziaWGPrefs{}, errors.New("random source is nil")
	}

	jc, err := randomUint16(rng, 3, 6)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	jmin, err := randomUint16(rng, 500, 700)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	jmax, err := randomUint16(rng, 800, 1000)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}

	minPrefix := uint16(5)
	if version == awgProfileV3 {
		// Header protection uses the first 12 prefix bytes as a nonce.
		minPrefix = 15
	}
	prefixes := [4]uint16{}
	for i := range prefixes {
		prefixes[i], err = randomUint16(rng, minPrefix, 32)
		if err != nil {
			return ipn.AmneziaWGPrefs{}, err
		}
	}

	config := ipn.AmneziaWGPrefs{
		JC:   jc,
		JMin: jmin,
		JMax: jmax,
		S1:   prefixes[0],
		S2:   prefixes[1],
		S3:   prefixes[2],
		S4:   prefixes[3],
	}

	headerBands := [...]struct{ min, max uint32 }{
		{100_000, 900_000_000},
		{1_000_000_000, 1_900_000_000},
		{2_000_000_000, 2_900_000_000},
		{3_000_000_000, 4_000_000_000},
	}
	headers := [4]ipn.MagicHeaderRange{}
	for i, band := range headerBands {
		base, err := randomUint32(rng, band.min, band.max-96)
		if err != nil {
			return ipn.AmneziaWGPrefs{}, err
		}
		headers[i] = ipn.MagicHeaderRange{Min: base, Max: base}
		if version == awgProfileV3 {
			width, err := randomUint32(rng, 16, 96)
			if err != nil {
				return ipn.AmneziaWGPrefs{}, err
			}
			headers[i].Max += width
		}
	}
	config.H1, config.H2, config.H3, config.H4 = headers[0], headers[1], headers[2], headers[3]

	if version == awgProfileV3 {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rng, key); err != nil {
			return ipn.AmneziaWGPrefs{}, err
		}
		config.HeaderProtectionKey = hex.EncodeToString(key)
		config.ContentPaddingAddition = ipn.MagicHeaderRange{Min: 5, Max: 31}
		config.RekeyAfterTime = ipn.MagicHeaderRange{Min: 120, Max: 180}
		config.RekeyTimeout = ipn.MagicHeaderRange{Min: 5, Max: 7}
		config.RejectAfterTime = ipn.MagicHeaderRange{Min: 180, Max: 240}
		config.KeepaliveTimeout = ipn.MagicHeaderRange{Min: 10, Max: 15}
		config.MaxHandshakeAttempts = ipn.MagicHeaderRange{Min: 8, Max: 12}
	}

	if err := validateAmneziaWGConfig(config); err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	return config, nil
}

func randomUint16(rng io.Reader, min, max uint16) (uint16, error) {
	value, err := randomUint32(rng, uint32(min), uint32(max))
	return uint16(value), err
}

func randomUint32(rng io.Reader, min, max uint32) (uint32, error) {
	if max < min {
		return 0, fmt.Errorf("invalid random range %d-%d", min, max)
	}
	var raw [4]byte
	if _, err := io.ReadFull(rng, raw[:]); err != nil {
		return 0, err
	}
	span := uint64(max) - uint64(min) + 1
	return min + uint32(uint64(binary.LittleEndian.Uint32(raw[:]))%span), nil
}
