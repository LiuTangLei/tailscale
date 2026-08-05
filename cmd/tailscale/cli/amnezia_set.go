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
	"fmt"
	"io"
	"os"
	"strings"

	"tailscale.com/ipn"
)

var errAWGSetupCancelled = errors.New("AmneziaWG setup cancelled")

type awgProfileVersion uint8

const (
	awgProfileV2 awgProfileVersion = 2
	awgProfileV3 awgProfileVersion = 3
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

func runAmneziaWGSet(ctx context.Context, args []string) error {
	config, err := parseConfigFromArgs(ctx, args)
	if errors.Is(err, errAWGSetupCancelled) {
		fmt.Println("No changes applied.")
		return nil
	}
	if err != nil {
		return err
	}

	if err := applyAmneziaWGConfig(ctx, config); err != nil {
		return err
	}

	fmt.Printf("%s configuration applied.\n", amneziaConfigVersion(config))
	return restartTailscaledWithPrompt()
}

// parseConfigFromArgs accepts one explicit JSON profile, or starts the concise
// profile generator when no argument is provided. JSON mode remains the
// advanced path for hand-authored fields and automation.
func parseConfigFromArgs(ctx context.Context, args []string) (ipn.AmneziaWGPrefs, error) {
	var config ipn.AmneziaWGPrefs
	switch len(args) {
	case 1:
		if err := json.Unmarshal([]byte(args[0]), &config); err != nil {
			return config, fmt.Errorf("invalid JSON: %w", err)
		}
		return config, nil
	case 0:
		return promptInteractiveConfig(ctx)
	default:
		return config, formatUsageError("tailscale amnezia-wg set [json-string]")
	}
}

func promptInteractiveConfig(ctx context.Context) (ipn.AmneziaWGPrefs, error) {
	curPrefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	return promptAWGProfile(
		bufio.NewScanner(os.Stdin),
		os.Stdout,
		cryptorand.Reader,
		curPrefs.AmneziaWG,
	)
}

func promptAWGProfile(scanner *bufio.Scanner, out io.Writer, rng io.Reader, current ipn.AmneziaWGPrefs) (ipn.AmneziaWGPrefs, error) {
	fmt.Fprintf(out, "AmneziaWG profile generator\nCurrent profile: %s\n\n", amneziaConfigVersion(current))
	fmt.Fprintln(out, "Select a profile to generate:")
	fmt.Fprintln(out, "  1) AWG v3 (recommended, default)")
	fmt.Fprintln(out, "  2) AWG v2 (legacy compatibility)")
	fmt.Fprintln(out, "  q) Cancel")
	fmt.Fprintln(out, "For custom fields, pass a JSON object directly to 'tailscale awg set'.")

	version, err := promptAWGProfileVersion(scanner, out)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
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
		case "q", "quit", "cancel":
			return 0, errAWGSetupCancelled
		default:
			fmt.Fprintln(out, "Enter 1 for AWG v3, 2 for AWG v2, or q to cancel.")
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
