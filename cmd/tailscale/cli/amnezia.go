// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"tailscale.com/types/key"
)

var amneziaCmd = &ffcli.Command{
	Name:       "amnezia-wg",
	ShortUsage: "tailscale amnezia-wg [subcommand]",
	ShortHelp:  "Manage native WG/AWG and experimental QUIC transports",
	LongHelp: `"tailscale awg" opens an interactive transport menu in a terminal.
Without a terminal it prints usage. "tailscale amnezia-wg" remains an alias,
and existing set/get/sync/reset/validate commands keep their AWG meaning.

Production modes:
  native    Existing WG/AWG. Zero AWG parameters mean standard WireGuard.
  quic-ip   Native IP over QUIC; no inner WireGuard or AWG parameters.
  http3-ip  Experimental native IP over HTTP/3; not a Chrome fingerprint clone.
WG-over-QUIC is development-only and is not offered by this command.

Use status to distinguish the active mode from a staged next-start mode.
transport changes never restart the daemon automatically. Environment or
embedding overrides must be removed separately before using managed profiles.

QUIC needs no client IP certificate and no AWG parameter sync, but peers still
need trusted PUBLIC identity cards. Use identity --init, identity, peer add,
then transport --yes quic-ip; restart deliberately and check status again.
Never copy the private daemon profile file to another node.

For native AWG only, communicating nodes must agree on H1-H4, S1-S4 and the
header-protection key. Existing awg sync continues to manage those parameters.`,
	Exec: runAWGRoot,
	Subcommands: []*ffcli.Command{
		{
			Name:       "sync",
			ShortUsage: "tailscale amnezia-wg sync",
			ShortHelp:  "Sync Amnezia-WG config from online peers",
			LongHelp:   `List all online peers with non-zero Amnezia-WG config, preview and sync config to local node.`,
			Exec:       runAmneziaWGSync,
		},
		{
			Name:       "set",
			ShortUsage: "tailscale amnezia-wg set [json-string]",
			ShortHelp:  "Generate or apply an AWG v2/v3 profile",
			LongHelp: `Generate or apply an AmneziaWG profile.

With no JSON argument, the concise generator offers:
  1) AWG v3 (recommended and selected by default)
  2) AWG v2 (for legacy peers)

The generated JSON is printed before confirmation. Copy that exact JSON to
every peer that must communicate with this node. S1-S4, H1-H4 and, for v3,
HeaderProtectionKey must match.

For Docker, scripts, desktop automation, or advanced fields, pass JSON directly:
  tailscale awg set '{"jc":5,"jmin":500,"jmax":1000,"s1":15,"s2":18,"s3":20,"s4":25,"h1":123456,"h2":67543,"h3":123123,"h4":32345}'

Historical v2 JSON remains accepted, except for the retired <c> CPS packet
counter tag removed by AmneziaWG 2.0. Remove <c> while keeping the other CPS
tags. A v2 profile clears all v3-only device state. After applying a profile,
restart tailscaled or restart the container.`,
			Exec: runAmneziaWGSet,
		},
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
			ShortUsage: "tailscale amnezia-wg reset",
			ShortHelp:  "Reset to standard WireGuard with optional restart",
			LongHelp: `Reset all Amnezia-WG parameters to zero (standard WireGuard).
After resetting, you will be prompted to restart tailscaled.`,
			Exec: runAmneziaWGReset,
		},
		transportStatusCommand(),
		transportCommand(),
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

// applyAmneziaWGConfig applies the Amnezia-WG configuration.
func applyAmneziaWGConfig(ctx context.Context, config ipn.AmneziaWGPrefs) error {
	if err := validateAmneziaWGConfig(config); err != nil {
		return err
	}
	maskedPrefs := createMaskedPrefs(config)
	_, err := localClient.EditPrefs(ctx, maskedPrefs)
	return err
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
	if len(args) != 0 {
		return formatUsageError("tailscale awg reset")
	}

	// Reset to all zeros (standard WireGuard)
	config := ipn.AmneziaWGPrefs{} // All zero values
	if err := applyAmneziaWGConfig(ctx, config); err != nil {
		return err
	}

	fmt.Println("Amnezia-WG configuration reset to standard WireGuard.")
	return restartTailscaledWithPrompt()
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
	if len(args) != 0 {
		return formatUsageError("tailscale awg sync")
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

	// Request AWG configs from all online peers (with structured output & stats)
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

	// Display found configurations and let user choose (compact list)
	fmt.Printf("Found AWG configurations on %d peer(s):\n\n", len(peerConfigs))
	for i, pc := range peerConfigs {
		fmt.Printf("[%d] %s (%s)\n", i+1, pc.PeerName, pc.PeerIP)
		printCompactAWGConfig(pc.Config)
		fmt.Println()
	}

	// Interactive selection and sync
	return handleInteractiveConfigSync(ctx, peerConfigs)
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
	scanner := bufio.NewScanner(os.Stdin)

selectionLoop:
	for {
		fmt.Println("Select a configuration to sync to this node:")
		fmt.Println("0. Cancel (keep current configuration)")
		for i, pc := range peerConfigs {
			fmt.Printf("%d. Sync from %s (%s)\n", i+1, pc.PeerName, pc.PeerIP)
		}

		fmt.Print("\nChoice [0]: ")
		if !scanner.Scan() { // EOF or error -> treat as cancel
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

		// Confirm/apply loop
		for {
			fmt.Print("\nApply this configuration? [Y/n=return to list]: ")
			if !scanner.Scan() {
				fmt.Println("\nCancelled.")
				return nil
			}
			ansRaw := strings.TrimSpace(scanner.Text())
			if ansRaw == "" { // default yes
				ansRaw = "y"
			}
			ans := strings.ToLower(ansRaw)

			switch ans {
			case "y", "yes":
				if err := applyAmneziaWGConfig(ctx, selected.Config); err != nil {
					return fmt.Errorf("failed to apply configuration: %w", err)
				}
				fmt.Printf("✓ AWG configuration synced from %s\n", selected.PeerName)
				return restartTailscaledWithPrompt()
			case "n", "no":
				fmt.Println("Not applied. Returning to list.")
				continue selectionLoop
			default:
				fmt.Println("Please answer Y (apply) or N (return to list).")
			}
		}
	}
}

// restartTailscaledWithPrompt asks user if they want to restart tailscaled and handles the restart.
func restartTailscaledWithPrompt() error {
	if !canRestartTailscaledAutomatically() {
		fmt.Println(tailscaledManualRestartHint())
		return nil
	}

	fmt.Print("Restart Tailscale now to apply changes? [Y/n]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Printf("\nSkipped restart because no interactive input is available. %s\n", tailscaledManualRestartHint())
		return nil
	}
	response := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if response == "" || response == "y" || response == "yes" {
		fmt.Println("Restarting Tailscale...")
		if err := restartTailscaled(); err != nil {
			return fmt.Errorf("failed to restart Tailscale: %w\n%s", err, tailscaledManualRestartHint())
		}
		fmt.Println("Tailscale restarted successfully.")
	} else {
		fmt.Printf("Skipped restart. %s\n", tailscaledManualRestartHint())
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
