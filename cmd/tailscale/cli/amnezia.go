// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	ShortHelp:  "Configure Amnezia-WG parameters",
	LongHelp: `"tailscale amnezia-wg" allows configuring Amnezia-WG parameters.
Amnezia-WG is backward compatible with standard WireGuard when all parameters are zero.

⚠️  CRITICAL: Certain parameters require network-wide consistency!
- H1-H4 (header fields): ALL nodes must use IDENTICAL values
- S1/S2 (prefix lengths): ALL nodes must use IDENTICAL values
- I1-I5, JC, JMin, JMax: Can differ between nodes

Use 'tailscale amnezia-wg get' on one node and 'tailscale amnezia-wg set' on others to maintain consistency for required parameters.`,
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
			ShortHelp:  "Set Amnezia-WG parameters with optional restart",
			LongHelp: `Set Amnezia-WG parameters either from JSON string or interactively.
After applying changes, you will be prompted to restart tailscaled.

⚠️  Network consistency requirements:
- H1-H4 (header fields): Must be IDENTICAL on ALL nodes
- S1/S2 (prefix lengths): Must be IDENTICAL on ALL nodes
- I1-I5, JC, JMin, JMax: Can differ between nodes

Examples:
	# Basic DPI evasion (junk packets only, compatible with standard WireGuard)
	tailscale amnezia-wg set '{"jc":4,"jmin":64,"jmax":96}'

	# Advanced protocol masking with captured protocol header
	tailscale amnezia-wg set '{"jc":4,"jmin":64,"jmax":96,"s1":10,"s2":15,"i1":"<b 0xc0000000><c><t>"}'

	# Header field parameters with junk packets
	tailscale amnezia-wg set '{"jc":4,"jmin":64,"jmax":96,"h1":3847291638,"h2":1029384756,"h3":2847291047,"h4":3918472658}'

	# Combined header fields and signature parameters
	tailscale amnezia-wg set '{"jc":4,"h1":3847291638,"h2":1029384756,"i1":"<b 0x12345678><r 16>"}'

  # Interactive configuration (recommended for beginners)
  tailscale amnezia-wg set

Note: Use Wireshark/tcpdump to capture real protocol headers for effective CPS signatures.
Guide: https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted`,
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
	},
}

// awgCmd is an alias for amneziaCmd to provide the shorter "tailscale awg" command
var awgCmd = &ffcli.Command{
	Name:        "awg",
	ShortUsage:  "tailscale awg [subcommand]",
	ShortHelp:   "Configure Amnezia-WG parameters (alias for amnezia-wg)",
	LongHelp:    amneziaCmd.LongHelp,
	Subcommands: amneziaCmd.Subcommands,
}

func runAmneziaWGSet(ctx context.Context, args []string) error {
	config, err := parseConfigFromArgs(ctx, args)
	if err != nil {
		return err
	}

	if err := applyAmneziaWGConfig(ctx, config); err != nil {
		return err
	}

	fmt.Println("Amnezia-WG configuration updated successfully.")
	return restartTailscaledWithPrompt()
}

// parseConfigFromArgs parses Amnezia-WG configuration from command line arguments or prompts interactively.
func parseConfigFromArgs(ctx context.Context, args []string) (ipn.AmneziaWGPrefs, error) {
	var config ipn.AmneziaWGPrefs

	switch len(args) {
	case 1:
		// Parse JSON argument
		if err := json.Unmarshal([]byte(args[0]), &config); err != nil {
			return config, fmt.Errorf("invalid JSON: %w", err)
		}
	case 0:
		// Interactive configuration
		var err error
		config, err = promptInteractiveConfig(ctx)
		if err != nil {
			return config, err
		}
	default:
		return config, formatUsageError("tailscale amnezia-wg set [json-string]")
	}

	return config, nil
}

// promptInteractiveConfig prompts the user to configure Amnezia-WG parameters interactively.
func promptInteractiveConfig(ctx context.Context) (ipn.AmneziaWGPrefs, error) {
	curPrefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return ipn.AmneziaWGPrefs{}, err
	}
	config := curPrefs.AmneziaWG

	printInteractiveConfigHeader()
	scanner := bufio.NewScanner(os.Stdin)

	// Basic parameters
	config.JC = promptUint16WithRange(scanner, "Junk packet count", config.JC, "0-10", "Recommended: 3-6 for basic DPI evasion")
	config.JMin = promptUint16WithRange(scanner, "Min junk packet size (bytes)", config.JMin, "64-1024", "Recommended: 64-128; must be ≥64 and ≤ JMax")
	config.JMax = promptUint16WithRange(scanner, "Max junk packet size (bytes)", config.JMax, "64-1024", "Recommended: 128-256; must be ≥ JMin")
	config.S1 = promptUint16WithRange(scanner, "Init packet prefix length (S1)", config.S1, "0-64", "Recommended: 10-20, breaks standard WG compatibility, MUST match all nodes")
	config.S2 = promptUint16WithRange(scanner, "Response packet prefix length (S2)", config.S2, "0-64", "Recommended: 10-20, breaks standard WG compatibility, MUST match all nodes")

	// Header parameters
	promptHeaderParameters(scanner, &config)

	// CPS parameters
	promptCPSParameters(scanner, &config)

	return config, nil
}

// printInteractiveConfigHeader prints the header information for interactive configuration.
func printInteractiveConfigHeader() {
	fmt.Println("Configure Amnezia-WG parameters (press Enter to keep current value, 0 or empty to disable):")
	fmt.Println("⚠️  H1-H4 and S1/S2 must be IDENTICAL on all nodes. I1-I5, JC, JMin, JMax can differ.")
	fmt.Println("Tip: For maximum compatibility, use junk packets only. For advanced DPI evasion, add CPS signatures.")
}

// promptHeaderParameters prompts for header field parameters (H1-H4).
func promptHeaderParameters(scanner *bufio.Scanner, config *ipn.AmneziaWGPrefs) {
	printSectionHeader("Header Field Parameters (h1-h4)")
	fmt.Println("These parameters provide basic protocol obfuscation using 32-bit random values.")
	fmt.Println("💡 Tip: Enter 'random' to auto-generate a 32-bit random number")
	fmt.Println("⚠️  If ANY node sets these values, ALL nodes in the network must use IDENTICAL values!")
	fmt.Println("👉  All-or-none: If H1 is 0 (disabled), H2-H4 will also be disabled & skipped.")

	config.H1 = promptUint32WithHint(scanner, "Header field 1 (H1)", config.H1, "32-bit random number (0-4294967295); enter 0 to disable all header fields")
	if config.H1 == 0 {
		config.H2, config.H3, config.H4 = 0, 0, 0
		fmt.Println("H1 disabled -> Skipping H2-H4 (all header fields disabled).")
	} else {
		for i, field := range []*uint32{&config.H2, &config.H3, &config.H4} {
			*field = promptUint32WithHint(scanner, fmt.Sprintf("Header field %d (H%d)", i+2, i+2), *field, "32-bit random number (0-4294967295)")
		}
	}
}

// promptCPSParameters prompts for Custom Protocol Signature parameters (I1-I5).
func promptCPSParameters(scanner *bufio.Scanner, config *ipn.AmneziaWGPrefs) {
	printSectionHeader("Custom Protocol Signature (CPS) Packets - Advanced Protocol Masking")
	printCPSInstructions()

	config.I1 = promptStringWithExample(scanner, "Primary signature packet (I1)", config.I1, "Leave empty for standard WireGuard compatibility (use JSON for long signatures >1000 chars)")
	if config.I1 != "" {
		names := []string{"Secondary", "Tertiary", "Quaternary", "Quinary"}
		for i, field := range []*string{&config.I2, &config.I3, &config.I4, &config.I5} {
			prompt := fmt.Sprintf("%s signature packet (I%d)", names[i], i+2)
			*field = promptStringWithExample(scanner, prompt, *field, "Optional entropy packet (use JSON for long signatures)")
		}
	} else {
		fmt.Println("Skipping I2-I5 (I1 is empty - standard WireGuard compatibility mode)")
	}
}

// printSectionHeader prints a section header with consistent formatting.
func printSectionHeader(title string) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", 70))
}

// printCPSInstructions prints detailed instructions for CPS configuration.
func printCPSInstructions() {
	instructions := []string{
		"Format: <b hex_data> | <c> (counter) | <t> (timestamp) | <r length> (random)",
		"Note: If I1 is empty, signature chain (I2-I5) is skipped",
		"\nTo create effective CPS signatures:",
		"1. Capture real protocol packets with Wireshark or tcpdump",
		"2. Extract hex patterns from packet headers",
		"3. Use <b hex_pattern> for static protocol headers",
		"4. Add <c>, <t>, <r length> for dynamic fields",
		"",
		"📖 Complete guide: https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted",
		"",
		"💡 For long CPS signatures (real packet captures), use JSON mode:",
		"   tailscale amnezia-wg set '{\"i1\":\"<b 0x...very_long_hex...>\"}'",
		"",
		"Basic format examples:",
		"  Static header only:     <b 0xc0000000>",
		"  With random padding:    <b 0x1234><r 16>",
		"  With counter+timestamp: <b 0xabcd><c><t>",
		"",
		"⚠️  Terminal Input Limitation:",
		"  For long CPS signatures (>1000 chars), terminal input may be truncated.",
		"  Use JSON mode instead: tailscale amnezia-wg set '{\"i1\":\"<your_long_cps>\"}'",
		"",
	}
	for _, line := range instructions {
		fmt.Println(line)
	}
}

// applyAmneziaWGConfig applies the Amnezia-WG configuration.
func applyAmneziaWGConfig(ctx context.Context, config ipn.AmneziaWGPrefs) error {
	maskedPrefs := createMaskedPrefs(config)
	_, err := localClient.EditPrefs(ctx, maskedPrefs)
	return err
}

func runAmneziaWGGet(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return formatUsageError("tailscale amnezia-wg get")
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

	// Basic parameters
	fmt.Printf("  JC (junk packet count): %d\n", config.JC)
	fmt.Printf("  JMin (min junk size): %d\n", config.JMin)
	fmt.Printf("  JMax (max junk size): %d\n", config.JMax)
	fmt.Printf("  S1 (init packet prefix length): %d\n", config.S1)
	fmt.Printf("  S2 (response packet prefix length): %d\n", config.S2)

	// Signature parameters
	fmt.Printf("  I1 (primary signature packet): %s\n", config.I1)
	fmt.Printf("  I2 (secondary signature packet): %s\n", config.I2)
	fmt.Printf("  I3 (tertiary signature packet): %s\n", config.I3)
	fmt.Printf("  I4 (quaternary signature packet): %s\n", config.I4)
	fmt.Printf("  I5 (quinary signature packet): %s\n", config.I5)

	// Header parameters
	fmt.Printf("  H1 (header field 1): %d\n", config.H1)
	fmt.Printf("  H2 (header field 2): %d\n", config.H2)
	fmt.Printf("  H3 (header field 3): %d\n", config.H3)
	fmt.Printf("  H4 (header field 4): %d\n", config.H4)
}

// isConfigZero checks if the Amnezia-WG configuration is all zero values.
func isConfigZero(config ipn.AmneziaWGPrefs) bool {
	return config.JC == 0 && config.JMin == 0 && config.JMax == 0 &&
		config.S1 == 0 && config.S2 == 0 &&
		config.I1 == "" && config.I2 == "" && config.I3 == "" && config.I4 == "" && config.I5 == "" &&
		config.H1 == 0 && config.H2 == 0 && config.H3 == 0 && config.H4 == 0
}

// formatConfigAsJSON formats the configuration as a compact JSON string.
func formatConfigAsJSON(config ipn.AmneziaWGPrefs) (string, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "")
	if err := encoder.Encode(config); err != nil {
		return "", err
	}
	// Remove the trailing newline that Encode adds
	return strings.TrimRight(buf.String(), "\n"), nil
}

func runAmneziaWGReset(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return formatUsageError("tailscale amnezia-wg reset")
	}

	// Reset to all zeros (standard WireGuard)
	config := ipn.AmneziaWGPrefs{} // All zero values
	if err := applyAmneziaWGConfig(ctx, config); err != nil {
		return err
	}

	fmt.Println("Amnezia-WG configuration reset to standard WireGuard.")
	return restartTailscaledWithPrompt()
}

func promptUint16(scanner *bufio.Scanner, prompt string, current uint16) uint16 {
	if val, err := promptUintGeneric(scanner, prompt, uint64(current), 16); err == nil {
		return uint16(val)
	}
	return current
}

func promptUint32(scanner *bufio.Scanner, prompt string, current uint32) uint32 {
	if val, err := promptUintGeneric(scanner, prompt, uint64(current), 32); err == nil {
		return uint32(val)
	}
	return current
}

// promptUintGeneric handles both uint16 and uint32 prompting with common logic
func promptUintGeneric(scanner *bufio.Scanner, prompt string, current uint64, bitSize int) (uint64, error) {
	fmt.Printf("%s [%d]: ", prompt, current)
	if !scanner.Scan() {
		return current, nil
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return current, nil
	}
	if val, err := strconv.ParseUint(text, 10, bitSize); err == nil {
		return val, nil
	}
	fmt.Printf("Invalid value, keeping current: %d\n", current)
	return current, fmt.Errorf("invalid value")
}

func promptUint32WithHint(scanner *bufio.Scanner, prompt string, current uint32, hint string) uint32 {
	displayValue := fmt.Sprintf("%d", current)
	if current == 0 {
		displayValue = "0 (disabled)"
	}

	fmt.Printf("%s [%s]: ", prompt, displayValue)
	if hint != "" {
		fmt.Printf("\n  💡 %s\n  > ", hint)
	}

	if !scanner.Scan() {
		return current
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return current
	}

	// Check for special keywords
	if strings.ToLower(text) == "random" || strings.ToLower(text) == "rand" {
		// Generate a random 32-bit number
		randomValue := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
		fmt.Printf("Generated random value: %d\n", randomValue)
		return randomValue
	}

	if val, err := strconv.ParseUint(text, 10, 32); err == nil {
		result := uint32(val)
		return result
	}

	fmt.Printf("Invalid value '%s', keeping current: %d\n", text, current)
	fmt.Println("Tip: Enter 'random' to generate a random 32-bit number")
	return current
}

func promptString(scanner *bufio.Scanner, prompt string, current string) string {
	return promptStringWithExample(scanner, prompt, current, "")
}

func promptStringWithExample(scanner *bufio.Scanner, prompt string, current string, hint string) string {
	displayValue := current
	if displayValue == "" {
		displayValue = "(empty)"
	}

	fmt.Printf("%s [%s]: ", prompt, displayValue)
	if hint != "" {
		fmt.Printf("\n  💡 %s\n  > ", hint)
	}

	if !scanner.Scan() {
		return current
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return current
	}
	return text
}

func promptUint16WithRange(scanner *bufio.Scanner, prompt string, current uint16, validRange string, hint string) uint16 {
	displayValue := "0 (disabled)"
	if current != 0 {
		displayValue = fmt.Sprintf("%d", current)
	}

	fmt.Printf("%s (%s) [%s]: ", prompt, validRange, displayValue)
	if hint != "" {
		fmt.Printf("\n  💡 %s\n  > ", hint)
	}

	if !scanner.Scan() {
		return current
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return current
	}

	val, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		fmt.Printf("Invalid value '%s', keeping current: %d\n", text, current)
		return current
	}

	result := uint16(val)
	// Simplified range validation
	if (strings.Contains(prompt, "Junk packet count") && result > 10) ||
		(strings.Contains(prompt, "junk packet size") && result > 0 && (result < 64 || result > 1024)) ||
		(strings.Contains(prompt, "prefix length") && result > 64) {
		fmt.Printf("Warning: Value %d is outside recommended range, but continuing...\n", result)
	}
	return result
}

func runAmneziaWGValidate(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return formatUsageError("tailscale amnezia-wg validate")
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	config := prefs.AmneziaWG
	fmt.Println("Amnezia-WG Configuration Validation")
	fmt.Println("===================================")

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
	hasHeader := config.H1 != 0 || config.H2 != 0 || config.H3 != 0 || config.H4 != 0
	hasSignature := config.I1 != "" || config.I2 != "" || config.I3 != "" || config.I4 != "" || config.I5 != ""
	hasJunk := config.JC != 0 || config.JMin != 0 || config.JMax != 0
	hasPrefix := config.S1 != 0 || config.S2 != 0

	fmt.Printf("⚠️  Status: Amnezia-WG mode enabled\n📊 Parameter Summary:\n")
	fmt.Printf("   - Junk packets: %s\n", formatEnabled(hasJunk))
	fmt.Printf("   - Prefix lengths (S1/S2): %s\n", formatEnabled(hasPrefix))
	fmt.Printf("   - Header parameters (H1-H4): %s\n", formatEnabled(hasHeader))
	fmt.Printf("   - Signature parameters (I1-I5): %s\n\n", formatEnabled(hasSignature))

	fmt.Printf("🔍 Compatibility Analysis:\n")
	if hasJunk && !hasPrefix && !hasHeader && !hasSignature {
		fmt.Printf("✅ Junk packets only: Compatible with standard WireGuard clients\n✅ Low impact: Should work with most configurations\n")
	} else {
		fmt.Printf("⚠️  Protocol modification: NOT compatible with standard WireGuard\n❌ Breaking changes: S1/S2, H1-H4, or I1-I5 parameters are set\n")
	}

	if hasHeader && hasSignature {
		fmt.Printf("⚠️  Mixed parameter types: Both header (H1-H4) and signature (I1-I5) parameters detected\n💡 Recommendation: Use either header OR signature parameters, not both\n")
	}

	if hasHeader && config.H1 > 0 && config.H1 < 1000000 {
		fmt.Printf("💡 Note: H1-H4 should use 32-bit random numbers for better obfuscation\n   Consider using larger random values (e.g., 3847291638)\n")
	}

	fmt.Printf("\n🚨 CRITICAL NETWORK REQUIREMENT:\n   These parameters MUST be IDENTICAL on ALL nodes: H1-H4, S1/S2\n   These parameters CAN differ between nodes: I1-I5, JC/JMin/JMax\n\n")
	fmt.Printf("📋 Required Actions for H1-H4 and S1/S2:\n   1. Get values: tailscale amnezia-wg get\n   2. Apply on all nodes: tailscale amnezia-wg set\n   3. Restart tailscaled on ALL nodes\n   4. Test connectivity\n\n")
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
		fmt.Println("No AWG configurations found on online peers.")
		fmt.Println("All peers are using standard WireGuard (no Amnezia-WG parameters).")
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
			IP:      ip,
			Name:    ps.HostName,
			NodeKey: ps.PublicKey, // Use NodeKey for now, disco key lookup needs different approach
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
	awgSyncMaxConcurrent  = 10              // max concurrent disco requests
	awgSyncPerPeerTimeout = 5 * time.Second // per peer request timeout
)

// requestAWGConfigsFromPeers requests AWG configurations from all peers using disco protocol
// and prints per-peer results in a deterministic order while still performing requests concurrently.
func requestAWGConfigsFromPeers(ctx context.Context, peers []peerInfo) ([]peerAWGConfig, awgDiscoveryStats, error) {
	start := time.Now()
	var (
		wg      sync.WaitGroup
		configs []peerAWGConfig
		mu      sync.Mutex
	)

	type result struct {
		idx    int
		peer   peerInfo
		cfg    ipn.AmneziaWGPrefs
		err    error
		dur    time.Duration
		zero   bool
		failed bool
	}

	resultsCh := make(chan result, len(peers))
	sem := make(chan struct{}, awgSyncMaxConcurrent)

	for i, p := range peers {
		peer := p
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			peerCtx, cancel := context.WithTimeout(ctx, awgSyncPerPeerTimeout)
			defer cancel()
			reqStart := time.Now()
			cfg, err := requestAWGConfigFromPeer(peerCtx, peer.NodeKey)
			zero := isConfigZero(cfg)
			failed := err != nil
			if err == nil && !zero {
				mu.Lock()
				configs = append(configs, peerAWGConfig{PeerName: peer.Name, PeerIP: peer.IP, Config: cfg})
				mu.Unlock()
			}
			resultsCh <- result{idx: idx, peer: peer, cfg: cfg, err: err, dur: time.Since(reqStart), zero: zero, failed: failed}
		}()
	}

	// Close results channel after all goroutines finish
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results into slice indexed by original order for stable printing
	ordered := make([]result, len(peers))
	for r := range resultsCh {
		ordered[r.idx] = r
	}

	var stats awgDiscoveryStats
	stats.Total = len(peers)

	for _, r := range ordered {
		if r.failed {
			stats.Failed++
			fmt.Printf("[ERR] %s (%s): %v\n", r.peer.Name, r.peer.IP, r.err)
			continue
		}
		if r.zero {
			stats.Standard++
			fmt.Printf("[--] %s (%s): standard WireGuard\n", r.peer.Name, r.peer.IP)
		} else {
			stats.WithConfig++
			fmt.Printf("[OK] %s (%s): AWG config found (%.0fms)\n", r.peer.Name, r.peer.IP, float64(r.dur.Milliseconds()))
		}
	}

	stats.Duration = time.Since(start)
	return configs, stats, nil
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
	if config.H1 > 0 {
		parts = append(parts, fmt.Sprintf("H1=%d", config.H1))
	}
	if config.H2 > 0 {
		parts = append(parts, fmt.Sprintf("H2=%d", config.H2))
	}
	if config.H3 > 0 {
		parts = append(parts, fmt.Sprintf("H3=%d", config.H3))
	}
	if config.H4 > 0 {
		parts = append(parts, fmt.Sprintf("H4=%d", config.H4))
	}
	if config.I1 != "" {
		parts = append(parts, fmt.Sprintf("I1=%s", truncateString(config.I1, 20)))
	}

	if len(parts) > 0 {
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
	fmt.Print("Restart tailscaled now to apply changes? [Y/n]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		response := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if response == "" || response == "y" || response == "yes" {
			fmt.Println("Restarting tailscaled...")
			if err := restartTailscaled(); err != nil {
				return fmt.Errorf("failed to restart tailscaled: %w\nPlease restart tailscaled manually for changes to take effect", err)
			}
			fmt.Println("tailscaled restarted successfully.")
		} else {
			fmt.Println("Skipped restart. Please restart tailscaled manually for changes to take effect.")
		}
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
