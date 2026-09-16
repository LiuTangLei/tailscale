// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/paths"
	"tailscale.com/types/key"
)

var amneziaCmd = &ffcli.Command{
	Name:       "amnezia-wg",
	ShortUsage: "tailscale amnezia-wg [subcommand]",
	ShortHelp:  "Manage native WG/AWG and QUIC transport",
	LongHelp: `"tailscale awg" opens an interactive transport menu in a terminal.
Without a terminal it prints usage. "tailscale amnezia-wg" remains an alias,
and "tailscale awg set" offers AWG v3, AWG v2, or QUIC in one menu.

Modes:
  native    Existing WG/AWG. Zero AWG parameters mean standard WireGuard.
  quic      QUIC with built-in obfuscation and automatic node-key trust.
Selecting QUIC automatically clears the saved AWG profile after confirmation.
The old http3-ip name remains accepted for scripts and saved configurations.

Use status to distinguish the active mode from a staged next-start mode.
Transport changes restart automatically by default unless --no-restart is set.
Environment or embedding overrides must be removed separately before using
managed profiles.

QUIC prepares its identity automatically and needs no AWG parameter sync.
Use set --yes quic to apply and verify the selection immediately.
All communicating nodes must enable compatible QUIC transport.
Never copy the private daemon profile file to another node.

For native AWG only, communicating nodes must agree on H1-H4, S1-S4 and the
header-protection key. Existing awg sync continues to manage those parameters.`,
	Exec: runAWGRoot,
	Subcommands: []*ffcli.Command{
		{
			Name:       "sync",
			ShortUsage: "tailscale amnezia-wg sync [--no-restart]",
			ShortHelp:  "Sync Amnezia-WG config from online peers",
			LongHelp:   `List all online peers with non-zero Amnezia-WG config, preview and sync config to local node. The daemon restarts automatically unless --no-restart is set.`,
			Exec: func(ctx context.Context, args []string) error {
				var noRestart bool
				fs := flag.NewFlagSet("sync", flag.ContinueOnError)
				fs.BoolVar(&noRestart, "no-restart", false, "stage the selected config without restarting the local daemon")
				if err := fs.Parse(args); err != nil {
					return err
				}
				return runAmneziaWGSyncWithOptions(ctx, fs.Args(), noRestart)
			},
		},
		awgSetCommand(),
		{
			Name:       "get",
			ShortUsage: "tailscale amnezia-wg get",
			ShortHelp:  "Get current Amnezia-WG parameters",
			Exec:       runAmneziaWGGet,
		},
		{
			Name:       "validate",
			ShortUsage: "tailscale amnezia-wg validate",
			ShortHelp:  "Validate current configuration and check network compatibility",
			LongHelp: `Validate the current Amnezia-WG configuration and provide compatibility guidance.
This helps identify potential connectivity issues before they occur.`,
			Exec: runAmneziaWGValidate,
		},
		{
			Name:       "reset",
			ShortUsage: "tailscale amnezia-wg reset [--no-restart]",
			ShortHelp:  "Reset to standard WireGuard and restart by default",
			LongHelp: `Reset all Amnezia-WG parameters to zero (standard WireGuard).
The daemon restarts automatically unless --no-restart is set.`,
			Exec: func(ctx context.Context, args []string) error {
				var noRestart bool
				fs := flag.NewFlagSet("reset", flag.ContinueOnError)
				fs.BoolVar(&noRestart, "no-restart", false, "leave the daemon staged without a restart")
				if err := fs.Parse(args); err != nil {
					return err
				}
				return runAmneziaWGResetWithOptions(ctx, fs.Args(), noRestart)
			},
		},
		transportStatusCommand(),
		transportCommand(),
		serverCommand(),
		identityCommand(),
		peerCommand(),
		doctorCommand(),
	},
}

// awgCmd is an alias for amneziaCmd to provide the shorter "tailscale awg" command
var awgCmd = &ffcli.Command{
	Name:        "awg",
	ShortUsage:  "tailscale awg [subcommand]",
	ShortHelp:   "Manage native WG/AWG and experimental QUIC transports",
	LongHelp:    amneziaCmd.LongHelp,
	Exec:        runAWGRoot,
	Subcommands: cloneAWGSubcommands(amneziaCmd.Subcommands),
}

func cloneAWGSubcommands(cmds []*ffcli.Command) []*ffcli.Command {
	if len(cmds) == 0 {
		return nil
	}
	cloned := make([]*ffcli.Command, len(cmds))
	for i, cmd := range cmds {
		clonedCmd := *cmd
		if strings.HasPrefix(clonedCmd.ShortUsage, "tailscale amnezia-wg") {
			clonedCmd.ShortUsage = strings.Replace(clonedCmd.ShortUsage, "tailscale amnezia-wg", "tailscale awg", 1)
		}
		clonedCmd.Subcommands = cloneAWGSubcommands(cmd.Subcommands)
		cloned[i] = &clonedCmd
	}
	return cloned
}

func ensureSafeLocalRestart() error {
	if localClient.Socket == "" || localClient.Socket == paths.DefaultTailscaledSocket() {
		return nil
	}
	return fmt.Errorf("refusing to restart the default tailscaled service with custom socket %q; restart that daemon separately", localClient.Socket)
}

func applyAndRestartAfterMutation(ctx context.Context, noRestart bool, out io.Writer, verify func(context.Context) error) error {
	if noRestart {
		if out != nil {
			fmt.Fprintln(out, "Change saved; daemon restart skipped (--no-restart).")
		}
		return nil
	}
	if err := ensureSafeLocalRestart(); err != nil {
		return err
	}
	if err := restartTailscaled(); err != nil {
		return fmt.Errorf("change saved but daemon restart failed: %w", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		err := verify(ctx)
		if err == nil {
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("change saved but did not become active after restart: %v", lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func waitForManagedMode(ctx context.Context, client transportClient, expectedMode string) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, err := getTransportStatusForClient(ctx, client)
		if err == nil {
			if !status.PendingRestart && status.ActiveMode == expectedMode && status.DesiredMode == expectedMode {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("active=%s desired=%s pending_restart=%t", status.ActiveMode, status.DesiredMode, status.PendingRestart)
			}
		} else if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func waitForServerState(ctx context.Context, client transportClient, expected bool) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, err := getTransportStatusForClient(ctx, client)
		if err == nil {
			if !status.PendingRestart && status.Server == expected {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("server=%t pending_restart=%t", status.Server, status.PendingRestart)
			}
		} else if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func waitForAWGConfig(ctx context.Context, client awgSetupClient, want ipn.AmneziaWGPrefs) error {
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, err := getTransportStatusForClient(ctx, client)
		if err == nil && status.PendingRestart {
			if time.Now().After(deadline) {
				return fmt.Errorf("active=%s desired=%s pending_restart=%t", status.ActiveMode, status.DesiredMode, status.PendingRestart)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		prefs, err := client.GetPrefs(ctx)
		if err == nil && prefs != nil && prefs.AmneziaWG == want {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			if status.PendingRestart {
				return fmt.Errorf("active=%s desired=%s pending_restart=%t", status.ActiveMode, status.DesiredMode, status.PendingRestart)
			}
			return fmt.Errorf("AWG config not active after restart: got %#v want %#v", prefs.AmneziaWG, want)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// applyAmneziaWGConfig is shared by set, sync and reset. Switching away from
// QUIC saves both the native selection and AWG profile before a single restart.
func applyAmneziaWGConfig(ctx context.Context, config ipn.AmneziaWGPrefs) error {
	return applyAmneziaWGConfigWithRestart(ctx, config, false, nil)
}

func applyAmneziaWGConfigWithRestart(ctx context.Context, config ipn.AmneziaWGPrefs, noRestart bool, out io.Writer) error {
	pending, err := applyAWGForClient(ctx, &localClient, config)
	if err != nil {
		return err
	}
	if pending && out != nil {
		fmt.Fprintf(out, "%s saved; native WG/AWG will activate after restart. The running QUIC transport has not changed.\n", amneziaConfigVersion(config))
	}
	if noRestart {
		if out != nil {
			fmt.Fprintf(out, "%s configuration staged for a later daemon restart (--no-restart).\n", amneziaConfigVersion(config))
		}
		return nil
	}
	return applyAndRestartAfterMutation(ctx, false, out, func(ctx context.Context) error {
		return waitForAWGConfig(ctx, &localClient, config)
	})
}

func applyAWGForClient(ctx context.Context, client awgSetupClient, config ipn.AmneziaWGPrefs) (bool, error) {
	if err := validateAmneziaWGConfig(config); err != nil {
		return false, err
	}
	status, err := getTransportStatusForClient(ctx, client)
	if err != nil && !errors.Is(err, errTransportUnavailable) {
		return false, err
	}
	if err == nil && (transportModeUsesQUIC(status.ActiveMode) || transportModeUsesQUIC(status.DesiredMode)) {
		if !status.Available || status.Source == "environment" || status.Source == "embedded" {
			return false, errors.New("transport is externally configured; remove that override before selecting AWG")
		}
		updated, err := configureTransportForClient(ctx, client, ipn.TransportControlRequest{
			Action: "awg", ExpectedRevision: status.Revision, AWG: &config,
		})
		if err != nil {
			return false, fmt.Errorf("select AWG (matching updated CLI and daemon required): %w", err)
		}
		return updated.PendingRestart, nil
	}
	// Native and older AWG-only daemons retain their ordinary LocalAPI path.
	_, err = client.EditPrefs(ctx, createMaskedPrefs(config))
	return false, err
}

func validateAmneziaWGConfig(config ipn.AmneziaWGPrefs) error {
	return ipn.ValidateAmneziaWGConfig(config)
}

func runAmneziaWGGet(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return formatUsageError("tailscale awg get")
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	config := prefs.AmneziaWG
	printAmneziaWGConfig(config)

	if !isConfigZero(config) {
		if jsonStr, err := formatConfigAsJSON(config); err == nil {
			fmt.Printf("\nJSON format:\n%s\n", jsonStr)
		}
	}

	return nil
}

// printAmneziaWGConfig prints the Amnezia-WG configuration in a formatted way.
func printAmneziaWGConfig(config ipn.AmneziaWGPrefs) {
	fmt.Printf("Current Amnezia-WG configuration:\n")
	fmt.Printf("  Profile version: %s\n", amneziaConfigVersion(config))

	// Basic parameters
	fmt.Printf("  JC (junk packet count): %d\n", config.JC)
	fmt.Printf("  JMin (min junk size): %d\n", config.JMin)
	fmt.Printf("  JMax (max junk size): %d\n", config.JMax)
	fmt.Printf("  S1 (init packet prefix length): %d\n", config.S1)
	fmt.Printf("  S2 (response packet prefix length): %d\n", config.S2)
	fmt.Printf("  S3 (cookie packet prefix length): %d\n", config.S3)
	fmt.Printf("  S4 (transport packet prefix length): %d\n", config.S4)

	// Signature parameters
	fmt.Printf("  I1 (primary signature packet): %s\n", config.I1)
	fmt.Printf("  I2 (secondary signature packet): %s\n", config.I2)
	fmt.Printf("  I3 (tertiary signature packet): %s\n", config.I3)
	fmt.Printf("  I4 (quaternary signature packet): %s\n", config.I4)
	fmt.Printf("  I5 (quinary signature packet): %s\n", config.I5)

	// Header parameters
	if config.H1.Min == config.H1.Max {
		fmt.Printf("  H1 (header field 1): %d\n", config.H1.Min)
	} else {
		fmt.Printf("  H1 (header field 1): %d-%d\n", config.H1.Min, config.H1.Max)
	}
	if config.H2.Min == config.H2.Max {
		fmt.Printf("  H2 (header field 2): %d\n", config.H2.Min)
	} else {
		fmt.Printf("  H2 (header field 2): %d-%d\n", config.H2.Min, config.H2.Max)
	}
	if config.H3.Min == config.H3.Max {
		fmt.Printf("  H3 (header field 3): %d\n", config.H3.Min)
	} else {
		fmt.Printf("  H3 (header field 3): %d-%d\n", config.H3.Min, config.H3.Max)
	}
	if config.H4.Min == config.H4.Max {
		fmt.Printf("  H4 (header field 4): %d\n", config.H4.Min)
	} else {
		fmt.Printf("  H4 (header field 4): %d-%d\n", config.H4.Min, config.H4.Max)
	}

	// AWG v3 parameters
	fmt.Printf("  HeaderProtectionKey: %s\n", valueOrDisabled(config.HeaderProtectionKey))
	fmt.Printf("  ContentPaddingAddition: %s\n", rangeOrDisabled(config.ContentPaddingAddition))
	fmt.Printf("  RekeyAfterTime: %s\n", rangeOrDisabled(config.RekeyAfterTime))
	fmt.Printf("  RekeyTimeout: %s\n", rangeOrDisabled(config.RekeyTimeout))
	fmt.Printf("  RejectAfterTime: %s\n", rangeOrDisabled(config.RejectAfterTime))
	fmt.Printf("  KeepaliveTimeout: %s\n", rangeOrDisabled(config.KeepaliveTimeout))
	fmt.Printf("  MaxHandshakeAttempts: %s\n", rangeOrDisabled(config.MaxHandshakeAttempts))
	fmt.Printf("  RandomTrailers: %t\n", config.RandomTrailers)
	fmt.Printf("  DisableCookies: %t\n", config.DisableCookies)
}

func hasV3Config(config ipn.AmneziaWGPrefs) bool {
	return config.IsV3()
}

func amneziaConfigVersion(config ipn.AmneziaWGPrefs) string {
	if isConfigZero(config) {
		return "standard WireGuard"
	}
	if config.IsV31() {
		return "AWG v3.1"
	}
	if hasV3Config(config) {
		return "AWG v3"
	}
	return "AWG v2"
}

func valueOrDisabled(value string) string {
	if value == "" {
		return "disabled"
	}
	return value
}

func rangeOrDisabled(value ipn.MagicHeaderRange) string {
	if value.IsZero() {
		return "disabled"
	}
	return value.String()
}

// isConfigZero checks if the Amnezia-WG configuration is all zero values.
func isConfigZero(config ipn.AmneziaWGPrefs) bool {
	return config.IsZero()
}

// formatConfigAsJSON formats the configuration as a compact JSON string.
func formatConfigAsJSON(config ipn.AmneziaWGPrefs) (string, error) {
	// Use stable, lower-case names for scripts and non-Go clients. Scalar
	// headers stay scalar for historical v2 consumers; ranges use the legacy
	// {min,max} object understood by both old v2 and current v3-capable peers.
	type canonicalAWGJSON struct {
		JC   uint16 `json:"jc,omitempty"`
		JMin uint16 `json:"jmin,omitempty"`
		JMax uint16 `json:"jmax,omitempty"`
		S1   uint16 `json:"s1,omitempty"`
		S2   uint16 `json:"s2,omitempty"`
		S3   uint16 `json:"s3,omitempty"`
		S4   uint16 `json:"s4,omitempty"`
		I1   string `json:"i1,omitempty"`
		I2   string `json:"i2,omitempty"`
		I3   string `json:"i3,omitempty"`
		I4   string `json:"i4,omitempty"`
		I5   string `json:"i5,omitempty"`

		H1 any `json:"h1,omitempty"`
		H2 any `json:"h2,omitempty"`
		H3 any `json:"h3,omitempty"`
		H4 any `json:"h4,omitempty"`

		HeaderProtectionKey    string `json:"header_protection_key,omitempty"`
		ContentPaddingAddition any    `json:"content_padding_addition,omitempty"`
		RekeyAfterTime         any    `json:"rekey_after_time,omitempty"`
		RekeyTimeout           any    `json:"rekey_timeout,omitempty"`
		RejectAfterTime        any    `json:"reject_after_time,omitempty"`
		KeepaliveTimeout       any    `json:"keepalive_timeout,omitempty"`
		MaxHandshakeAttempts   any    `json:"max_handshake_attempts,omitempty"`
		RandomTrailers         bool   `json:"random_trailers,omitempty"`
		DisableCookies         bool   `json:"disable_cookies,omitempty"`
	}
	rangeValue := func(value ipn.MagicHeaderRange) any {
		if value.IsZero() {
			return nil
		}
		if value.Min == value.Max {
			return value.Min
		}
		return value
	}
	canonical := canonicalAWGJSON{
		JC:                     config.JC,
		JMin:                   config.JMin,
		JMax:                   config.JMax,
		S1:                     config.S1,
		S2:                     config.S2,
		S3:                     config.S3,
		S4:                     config.S4,
		I1:                     config.I1,
		I2:                     config.I2,
		I3:                     config.I3,
		I4:                     config.I4,
		I5:                     config.I5,
		H1:                     rangeValue(config.H1),
		H2:                     rangeValue(config.H2),
		H3:                     rangeValue(config.H3),
		H4:                     rangeValue(config.H4),
		HeaderProtectionKey:    config.HeaderProtectionKey,
		ContentPaddingAddition: rangeValue(config.ContentPaddingAddition),
		RekeyAfterTime:         rangeValue(config.RekeyAfterTime),
		RekeyTimeout:           rangeValue(config.RekeyTimeout),
		RejectAfterTime:        rangeValue(config.RejectAfterTime),
		KeepaliveTimeout:       rangeValue(config.KeepaliveTimeout),
		MaxHandshakeAttempts:   rangeValue(config.MaxHandshakeAttempts),
		RandomTrailers:         config.RandomTrailers,
		DisableCookies:         config.DisableCookies,
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(canonical); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func runAmneziaWGReset(ctx context.Context, args []string) error {
	return runAmneziaWGResetWithOptions(ctx, args, false)
}

func runAmneziaWGResetWithOptions(ctx context.Context, args []string, noRestart bool) error {
	if len(args) != 0 {
		return formatUsageError("tailscale awg reset [--no-restart]")
	}

	config := ipn.AmneziaWGPrefs{}
	if err := applyAmneziaWGConfigWithRestart(ctx, config, noRestart, os.Stdout); err != nil {
		return err
	}
	fmt.Println("Amnezia-WG configuration reset to standard WireGuard.")
	return nil
}

func runAmneziaWGValidate(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return formatUsageError("tailscale awg validate")
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	config := prefs.AmneziaWG
	fmt.Println("Amnezia-WG Configuration Validation")
	fmt.Println("===================================")
	if err := validateAmneziaWGConfig(config); err != nil {
		return fmt.Errorf("invalid Amnezia-WG configuration: %w", err)
	}

	if isConfigZero(config) {
		fmt.Println("✅ Status: Standard WireGuard mode (all parameters disabled)")
		fmt.Println("✅ Compatibility: Full compatibility with all WireGuard clients")
		fmt.Println("✅ Network requirement: No special configuration needed on other nodes")
		return nil
	}

	printValidationSummary(config)
	printValidationWarnings(config)
	return nil
}

func printValidationSummary(config ipn.AmneziaWGPrefs) {
	hasHeader := (config.H1.Min != 0 || config.H1.Max != 0) || (config.H2.Min != 0 || config.H2.Max != 0) ||
		(config.H3.Min != 0 || config.H3.Max != 0) || (config.H4.Min != 0 || config.H4.Max != 0)
	hasSignature := config.I1 != "" || config.I2 != "" || config.I3 != "" || config.I4 != "" || config.I5 != ""
	hasJunk := config.JC != 0 || config.JMin != 0 || config.JMax != 0
	hasPrefix := config.S1 != 0 || config.S2 != 0 || config.S3 != 0 || config.S4 != 0
	hasV3 := hasV3Config(config)
	hasHeaderProtection := config.HeaderProtectionKey != "" && strings.Trim(config.HeaderProtectionKey, "0") != ""

	fmt.Printf("⚠️  Status: %s mode enabled\n📊 Parameter Summary:\n", amneziaConfigVersion(config))
	fmt.Printf("   - Junk packets: %s\n", formatEnabled(hasJunk))
	fmt.Printf("   - Prefix lengths (S1-S4): %s\n", formatEnabled(hasPrefix))
	fmt.Printf("   - Header parameters (H1-H4): %s\n", formatEnabled(hasHeader))
	fmt.Printf("   - Signature parameters (I1-I5): %s\n", formatEnabled(hasSignature))
	fmt.Printf("   - AWG v3 parameters: %s\n\n", formatEnabled(hasV3))

	fmt.Printf("🔍 Compatibility Analysis:\n")
	if !hasPrefix && !hasHeader && !hasHeaderProtection {
		fmt.Printf("✅ Wire-compatible obfuscation: Junk packets, I1-I5 signatures, and v3 timing/padding do not change standard WireGuard packet headers\n")
	} else {
		fmt.Printf("⚠️  Protocol modification: NOT compatible with standard WireGuard\n❌ Breaking changes: S1-S4, H1-H4, or HeaderProtectionKey are set\n")
	}
	if hasV3 {
		fmt.Printf("⚠️  AWG v3 profile: all participating nodes must run a v3-capable core\n")
	}

	if hasHeader && (config.H1.Min > 0 || config.H1.Max > 0) && (config.H1.Min < 1000000 && config.H1.Max < 1000000) {
		fmt.Printf("💡 Note: H1-H4 should use 32-bit random numbers for better obfuscation\n   Consider using larger random values (e.g., 3847291638)\n")
	}

	fmt.Printf("\n🚨 CRITICAL NETWORK REQUIREMENT:\n   These parameters MUST be IDENTICAL on ALL nodes: H1-H4, S1-S4, HeaderProtectionKey\n   These parameters CAN differ between nodes: I1-I5, JC/JMin/JMax, v3 padding/timing ranges\n\n")
	fmt.Printf("📋 Required Actions:\n   1. Get values: tailscale awg get\n   2. Apply on all nodes: tailscale awg set\n   3. Restart tailscaled on ALL nodes\n   4. Test connectivity\n\n")
}

func printValidationWarnings(config ipn.AmneziaWGPrefs) {
	if config.JMin > 0 && config.JMax > 0 && config.JMin > config.JMax {
		fmt.Printf("❌ Error: JMin (%d) is greater than JMax (%d)\n", config.JMin, config.JMax)
	}
	if config.JC > 10 {
		fmt.Printf("⚠️  Warning: JC (%d) is very high, may impact performance\n", config.JC)
	}
}

func formatEnabled(enabled bool) string {
	if enabled {
		return "Enabled ⚠️"
	}
	return "Disabled ✅"
}

// runAmneziaWGSync implements the sync logic using disco protocol to request AWG configs from peers.
func runAmneziaWGSync(ctx context.Context, args []string) error {
	return runAmneziaWGSyncWithOptions(ctx, args, false)
}

func runAmneziaWGSyncWithOptions(ctx context.Context, args []string, noRestart bool) error {
	if len(args) != 0 {
		return formatUsageError("tailscale awg sync [--no-restart]")
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	peers := collectOnlinePeersForDiscoSync(st)
	if len(peers) == 0 {
		fmt.Println("No online peers found.")
		return nil
	}

	fmt.Printf("Found %d online peers. Requesting AWG configurations via disco protocol...\n\n", len(peers))

	peerConfigs, stats, err := requestAWGConfigsFromPeers(ctx, peers)
	if err != nil {
		return fmt.Errorf("failed to request AWG configs: %w", err)
	}

	fmt.Printf("\nDiscovery summary: %d total | %d with AWG config | %d standard | %d failed | duration %.2fs\n\n",
		stats.Total, stats.WithConfig, stats.Standard, stats.Failed, stats.Duration.Seconds())

	if len(peerConfigs) == 0 {
		printNoAWGConfigs(os.Stdout, stats)
		return nil
	}

	fmt.Printf("Found AWG configurations on %d peer(s):\n\n", len(peerConfigs))
	for i, pc := range peerConfigs {
		fmt.Printf("[%d] %s (%s)\n", i+1, pc.PeerName, pc.PeerIP)
		printCompactAWGConfig(pc.Config)
		fmt.Println()
	}

	return handleInteractiveConfigSyncWithOptions(ctx, peerConfigs, noRestart)
}

// collectOnlinePeersForDiscoSync collects all online peers for potential disco-based sync
func collectOnlinePeersForDiscoSync(st *ipnstate.Status) []peerInfo {
	var peers []peerInfo
	for _, k := range st.Peers() {
		ps := st.Peer[k]
		if !ps.Online || ps.ShareeNode {
			continue
		}
		ip := ""
		if len(ps.TailscaleIPs) > 0 {
			ip = ps.TailscaleIPs[0].String()
		}
		peers = append(peers, peerInfo{
			IP:   ip,
			Name: ps.HostName,
			// The status map key is the authoritative peer identity. Older
			// LocalAPI producers did not always populate PublicKey.
			NodeKey: k,
		})
	}
	return peers
}

type peerInfo struct {
	IP      string
	Name    string
	NodeKey key.NodePublic // Node public key, will be used to lookup disco key
}

type peerAWGConfig struct {
	PeerName string
	PeerIP   string
	Config   ipn.AmneziaWGPrefs
}

// awgDiscoveryStats captures statistics from the discovery phase.
type awgDiscoveryStats struct {
	Total      int
	WithConfig int
	Standard   int
	Failed     int
	Duration   time.Duration
}

const (
	awgSyncMaxConcurrent     = 10
	awgSyncPerAttemptTimeout = 5 * time.Second
	awgSyncMaxAttempts       = 2
	awgSyncRetryDelay        = 250 * time.Millisecond
)

type awgSyncPolicy struct {
	MaxConcurrent  int
	AttemptTimeout time.Duration
	MaxAttempts    int
	RetryDelay     time.Duration
}

var defaultAWGSyncPolicy = awgSyncPolicy{
	MaxConcurrent:  awgSyncMaxConcurrent,
	AttemptTimeout: awgSyncPerAttemptTimeout,
	MaxAttempts:    awgSyncMaxAttempts,
	RetryDelay:     awgSyncRetryDelay,
}

type awgConfigRequester func(context.Context, key.NodePublic) (ipn.AmneziaWGPrefs, error)

type awgPeerDiscoveryResult struct {
	peer     peerInfo
	config   ipn.AmneziaWGPrefs
	err      error
	duration time.Duration
	attempts int
}

// requestAWGConfigsFromPeers requests AWG configurations from all peers using disco protocol
// and prints per-peer results in a deterministic order while still performing requests concurrently.
func requestAWGConfigsFromPeers(ctx context.Context, peers []peerInfo) ([]peerAWGConfig, awgDiscoveryStats, error) {
	return requestAWGConfigsFromPeersWith(ctx, peers, requestAWGConfigFromPeer, defaultAWGSyncPolicy, os.Stdout)
}

func requestAWGConfigsFromPeersWith(ctx context.Context, peers []peerInfo, request awgConfigRequester, policy awgSyncPolicy, out io.Writer) ([]peerAWGConfig, awgDiscoveryStats, error) {
	if request == nil || out == nil || policy.MaxConcurrent < 1 || policy.AttemptTimeout <= 0 || policy.MaxAttempts < 1 || policy.RetryDelay < 0 {
		return nil, awgDiscoveryStats{}, errors.New("invalid AWG sync policy")
	}

	start := time.Now()
	results := make([]awgPeerDiscoveryResult, len(peers))
	sem := make(chan struct{}, policy.MaxConcurrent)
	var wg sync.WaitGroup

	for i, p := range peers {
		wg.Add(1)
		go func(i int, peer peerInfo) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = awgPeerDiscoveryResult{peer: peer, err: ctx.Err()}
				return
			}
			defer func() { <-sem }()

			reqStart := time.Now()
			cfg, attempts, err := requestAWGConfigWithRetry(ctx, peer.NodeKey, request, policy)
			results[i] = awgPeerDiscoveryResult{
				peer:     peer,
				config:   cfg,
				err:      err,
				duration: time.Since(reqStart),
				attempts: attempts,
			}
		}(i, p)
	}
	wg.Wait()

	stats := awgDiscoveryStats{Total: len(peers)}
	configs := make([]peerAWGConfig, 0, len(peers))

	for _, r := range results {
		if r.err != nil {
			stats.Failed++
			if r.attempts > 1 {
				fmt.Fprintf(out, "[ERR] %s (%s) after %d attempts: %v\n", r.peer.Name, r.peer.IP, r.attempts, r.err)
			} else {
				fmt.Fprintf(out, "[ERR] %s (%s): %v\n", r.peer.Name, r.peer.IP, r.err)
			}
			continue
		}
		if r.config.IsZero() {
			stats.Standard++
			fmt.Fprintf(out, "[--] %s (%s): standard WireGuard\n", r.peer.Name, r.peer.IP)
		} else {
			stats.WithConfig++
			configs = append(configs, peerAWGConfig{PeerName: r.peer.Name, PeerIP: r.peer.IP, Config: r.config})
			if r.attempts > 1 {
				fmt.Fprintf(out, "[OK] %s (%s): AWG config found (%d attempts, %dms)\n", r.peer.Name, r.peer.IP, r.attempts, r.duration.Milliseconds())
			} else {
				fmt.Fprintf(out, "[OK] %s (%s): AWG config found (%dms)\n", r.peer.Name, r.peer.IP, r.duration.Milliseconds())
			}
		}
	}

	stats.Duration = time.Since(start)
	return configs, stats, nil
}

func requestAWGConfigWithRetry(ctx context.Context, nodeKey key.NodePublic, request awgConfigRequester, policy awgSyncPolicy) (ipn.AmneziaWGPrefs, int, error) {
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return ipn.AmneziaWGPrefs{}, attempt - 1, err
		}

		attemptCtx, cancel := context.WithTimeout(ctx, policy.AttemptTimeout)
		config, err := request(attemptCtx, nodeKey)
		cancel()
		if err == nil {
			return config, attempt, nil
		}
		lastErr = err
		if attempt == policy.MaxAttempts || !isRetryableAWGSyncError(err) || ctx.Err() != nil {
			return ipn.AmneziaWGPrefs{}, attempt, err
		}

		if policy.RetryDelay > 0 {
			timer := time.NewTimer(policy.RetryDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ipn.AmneziaWGPrefs{}, attempt, ctx.Err()
			}
		}
	}
	return ipn.AmneziaWGPrefs{}, policy.MaxAttempts, lastErr
}

func isRetryableAWGSyncError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var timeoutError interface{ Timeout() bool }
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "request timed out") ||
		strings.Contains(message, "context deadline exceeded") ||
		strings.Contains(message, "no path available")
}

func printNoAWGConfigs(out io.Writer, stats awgDiscoveryStats) {
	switch {
	case stats.Failed == 0:
		fmt.Fprintln(out, "No AWG configurations found on online peers.")
		fmt.Fprintln(out, "All peers are using standard WireGuard (no Amnezia-WG parameters).")
	case stats.Failed == stats.Total:
		fmt.Fprintf(out, "Unable to determine AWG configuration: all %d peer requests failed.\n", stats.Total)
		fmt.Fprintln(out, "Peers may be online in the control plane but temporarily unreachable via disco/DERP. Please retry.")
	default:
		fmt.Fprintf(out, "No AWG configurations could be confirmed: %d peer(s) reported standard WireGuard and %d request(s) failed.\n",
			stats.Standard, stats.Failed)
		fmt.Fprintln(out, "Failed peers were not classified as standard WireGuard. Please retry before syncing.")
	}
}

// requestAWGConfigFromPeer requests AWG configuration from a specific peer using disco protocol
func requestAWGConfigFromPeer(ctx context.Context, nodeKey key.NodePublic) (ipn.AmneziaWGPrefs, error) {
	return localClient.RequestAmneziaWGConfig(ctx, nodeKey)
}

// printCompactAWGConfig prints a compact summary of AWG configuration
func printCompactAWGConfig(config ipn.AmneziaWGPrefs) {
	var parts []string
	if config.JC > 0 {
		parts = append(parts, fmt.Sprintf("JC=%d", config.JC))
	}
	if config.JMin > 0 {
		parts = append(parts, fmt.Sprintf("JMin=%d", config.JMin))
	}
	if config.JMax > 0 {
		parts = append(parts, fmt.Sprintf("JMax=%d", config.JMax))
	}
	if config.S1 > 0 {
		parts = append(parts, fmt.Sprintf("S1=%d", config.S1))
	}
	if config.S2 > 0 {
		parts = append(parts, fmt.Sprintf("S2=%d", config.S2))
	}
	if config.S3 > 0 {
		parts = append(parts, fmt.Sprintf("S3=%d", config.S3))
	}
	if config.S4 > 0 {
		parts = append(parts, fmt.Sprintf("S4=%d", config.S4))
	}
	if config.H1.Min > 0 || config.H1.Max > 0 {
		if config.H1.Min == config.H1.Max {
			parts = append(parts, fmt.Sprintf("H1=%d", config.H1.Min))
		} else {
			parts = append(parts, fmt.Sprintf("H1=%d-%d", config.H1.Min, config.H1.Max))
		}
	}
	if config.H2.Min > 0 || config.H2.Max > 0 {
		if config.H2.Min == config.H2.Max {
			parts = append(parts, fmt.Sprintf("H2=%d", config.H2.Min))
		} else {
			parts = append(parts, fmt.Sprintf("H2=%d-%d", config.H2.Min, config.H2.Max))
		}
	}
	if config.H3.Min > 0 || config.H3.Max > 0 {
		if config.H3.Min == config.H3.Max {
			parts = append(parts, fmt.Sprintf("H3=%d", config.H3.Min))
		} else {
			parts = append(parts, fmt.Sprintf("H3=%d-%d", config.H3.Min, config.H3.Max))
		}
	}
	if config.H4.Min > 0 || config.H4.Max > 0 {
		if config.H4.Min == config.H4.Max {
			parts = append(parts, fmt.Sprintf("H4=%d", config.H4.Min))
		} else {
			parts = append(parts, fmt.Sprintf("H4=%d-%d", config.H4.Min, config.H4.Max))
		}
	}
	if config.I1 != "" {
		parts = append(parts, fmt.Sprintf("I1=%s", truncateString(config.I1, 20)))
	}
	if config.HeaderProtectionKey != "" {
		parts = append(parts, fmt.Sprintf("HeaderProtectionKey=%s", truncateString(config.HeaderProtectionKey, 12)))
	}
	for _, item := range []struct {
		name  string
		value ipn.MagicHeaderRange
	}{
		{"ContentPaddingAddition", config.ContentPaddingAddition},
		{"RekeyAfterTime", config.RekeyAfterTime},
		{"RekeyTimeout", config.RekeyTimeout},
		{"RejectAfterTime", config.RejectAfterTime},
		{"KeepaliveTimeout", config.KeepaliveTimeout},
		{"MaxHandshakeAttempts", config.MaxHandshakeAttempts},
	} {
		if !item.value.IsZero() {
			parts = append(parts, fmt.Sprintf("%s=%s", item.name, item.value.String()))
		}
	}

	if len(parts) > 0 {
		fmt.Printf("   Profile: %s\n", amneziaConfigVersion(config))
		fmt.Printf("   Parameters: %s\n", strings.Join(parts, ", "))
	} else {
		fmt.Printf("   Parameters: (standard WireGuard)\n")
	}
}

// handleInteractiveConfigSync handles interactive selection and syncing of AWG configs
func handleInteractiveConfigSync(ctx context.Context, peerConfigs []peerAWGConfig) error {
	return handleInteractiveConfigSyncWithOptions(ctx, peerConfigs, false)
}

func handleInteractiveConfigSyncWithOptions(ctx context.Context, peerConfigs []peerAWGConfig, noRestart bool) error {
	scanner := bufio.NewScanner(os.Stdin)

selectionLoop:
	for {
		fmt.Println("Select a configuration to sync to this node:")
		fmt.Println("0. Cancel (keep current configuration)")
		for i, pc := range peerConfigs {
			fmt.Printf("%d. Sync from %s (%s)\n", i+1, pc.PeerName, pc.PeerIP)
		}

		fmt.Print("\nChoice [0]: ")
		if !scanner.Scan() {
			fmt.Println("\nCancelled.")
			return nil
		}
		choice := strings.TrimSpace(scanner.Text())
		if choice == "" || choice == "0" {
			fmt.Println("Cancelled.")
			return nil
		}

		idx, err := strconv.Atoi(choice)
		if err != nil || idx < 1 || idx > len(peerConfigs) {
			fmt.Printf("Invalid choice: %s\n\n", choice)
			continue selectionLoop
		}
		selected := peerConfigs[idx-1]
		fmt.Printf("\nSelected configuration from %s:\n", selected.PeerName)
		printAmneziaWGConfig(selected.Config)

		for {
			fmt.Print("\nApply this configuration? [Y/n=return to list]: ")
			if !scanner.Scan() {
				fmt.Println("\nCancelled.")
				return nil
			}
			ansRaw := strings.TrimSpace(scanner.Text())
			if ansRaw == "" {
				ansRaw = "y"
			}
			ans := strings.ToLower(ansRaw)

			switch ans {
			case "y", "yes":
				if err := applyAmneziaWGConfigWithRestart(ctx, selected.Config, noRestart, os.Stdout); err != nil {
					return fmt.Errorf("failed to apply configuration: %w", err)
				}
				fmt.Printf("✓ AWG configuration synced from %s\n", selected.PeerName)
				return nil
			case "n", "no":
				fmt.Println("Not applied. Returning to list.")
				continue selectionLoop
			default:
				fmt.Println("Please answer Y (apply) or N (return to list).")
			}
		}
	}
}

// restartTailscaledWithPrompt performs an automatic restart without a second prompt.
func restartTailscaledWithPrompt() error {
	if !canRestartTailscaledAutomatically() {
		fmt.Println(tailscaledManualRestartHint())
		return nil
	}
	if err := ensureSafeLocalRestart(); err != nil {
		return err
	}
	if err := restartTailscaled(); err != nil {
		return fmt.Errorf("failed to restart Tailscale: %w\n%s", err, tailscaledManualRestartHint())
	}
	return nil
}

// formatUsageError formats usage error messages consistently.
func formatUsageError(usage string) error {
	return fmt.Errorf("usage: %s", usage)
}

// createMaskedPrefs creates a MaskedPrefs with AmneziaWG configuration.
func createMaskedPrefs(config ipn.AmneziaWGPrefs) *ipn.MaskedPrefs {
	return &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AmneziaWG: config,
		},
		AmneziaWGSet: true,
	}
}
