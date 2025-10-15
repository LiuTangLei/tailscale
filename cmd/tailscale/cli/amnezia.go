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
- S1-S4 (prefix lengths): ALL nodes must use IDENTICAL values
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
- S1-S4 (prefix lengths): Must be IDENTICAL on ALL nodes
- I1-I5, JC, JMin, JMax: Can differ between nodes

Examples:
	# Basic DPI evasion (junk packets only, compatible with standard WireGuard)
	tailscale amnezia-wg set '{"jc":4,"jmin":64,"jmax":96}'

	# Advanced protocol masking with captured protocol header
	tailscale amnezia-wg set '{"jc":4,"jmin":64,"jmax":96,"s1":10,"s2":15,"i1":"<b 0xc0000000><c><t>"}'

	# Header field parameters with junk packets (single values)
	tailscale amnezia-wg set '{"jc":4,"jmin":64,"jmax":96,"h1":3847291638,"h2":1029384756,"h3":2847291047,"h4":3918472658}'

	# Header field parameters with range values
	tailscale amnezia-wg set '{"jc":4,"jmin":64,"jmax":96,"h1":{"min":100,"max":200},"h2":{"min":300,"max":400}}'

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

	// Ask if user wants random generation
	fmt.Println("\n🎲 Quick Setup Option:")
	fmt.Print("Do you want to generate random AWG parameters automatically? [Y/n]: ")
	if scanner.Scan() {
		response := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if response == "" || response == "y" || response == "yes" {
			config = generateRandomAWGConfig()
			fmt.Println("\n✅ Random configuration generated successfully!")
			fmt.Println("💡 You can still customize I1-I5 signature parameters below if needed.\n")
			// Only ask for I1-I5 parameters in random mode
			promptCPSParameters(scanner, &config)
			return config, nil
		}
	}

	fmt.Println("\n📝 Manual Configuration Mode:")
	// Basic parameters
	config.JC = promptUint16WithRange(scanner, "Junk packet count", config.JC, "0-10", "Recommended: 3-6 for basic DPI evasion")

	// Only prompt for JMin/JMax if JC > 0
	if config.JC > 0 {
		config.JMin = promptUint16WithRange(scanner, "Min junk packet size (bytes)", config.JMin, "64-1024", "Recommended: 64-128; must be ≥64 and ≤ JMax")
		config.JMax = promptUint16WithRange(scanner, "Max junk packet size (bytes)", config.JMax, "64-1024", "Recommended: 128-256; must be ≥ JMin")
	} else {
		config.JMin = 0
		config.JMax = 0
		fmt.Println("📌 JC=0: Skipping JMin/JMax (no junk packets)")
	}

	// Prefix parameters - with random support
	promptPrefixParameters(scanner, &config)

	// Header parameters
	promptHeaderParameters(scanner, &config)

	// CPS parameters
	promptCPSParameters(scanner, &config)

	return config, nil
}

// printInteractiveConfigHeader prints the header information for interactive configuration.
func printInteractiveConfigHeader() {
	fmt.Println("Configure Amnezia-WG parameters (press Enter to keep current value, 0 or empty to disable):")
	fmt.Println("⚠️  H1-H4 and S1-S4 must be IDENTICAL on all nodes. I1-I5, JC, JMin, JMax can differ.")
	fmt.Println("💡 Quick tip: Choose random generation for instant setup, or manual for full control.")
	fmt.Println("📖 For maximum compatibility, use junk packets only. For advanced DPI evasion, add CPS signatures.")
}

// promptHeaderParameters prompts for header field parameters (H1-H4).
func promptHeaderParameters(scanner *bufio.Scanner, config *ipn.AmneziaWGPrefs) {
	printSectionHeader("Header Field Parameters (h1-h4)")
	fmt.Println("These parameters provide basic protocol obfuscation using 32-bit random values or ranges.")
	fmt.Println("💡 Tip: Enter 'random' at any prompt to auto-generate all H1-H4 min/max values")
	fmt.Println("⚠️  If ANY node sets these values, ALL nodes in the network must use IDENTICAL values!")
	fmt.Println("👉  All-or-none: If H1-min is 0 (disabled), all header fields will be disabled & skipped.")

	// H1 Min
	h1Min := promptUint32ForHeaderField(scanner, "Header field 1 Min (H1-min)", config.H1.Min, "32-bit random number (0-4294967295); enter 0 to disable all header fields")
	if h1Min == 0 {
		config.H1, config.H2, config.H3, config.H4 = ipn.MagicHeaderRange{}, ipn.MagicHeaderRange{}, ipn.MagicHeaderRange{}, ipn.MagicHeaderRange{}
		fmt.Println("H1-min disabled -> Skipping all header fields (all disabled).")
		return
	}

	// Check if user entered "random" and generate all values
	if h1Min == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}

	// H1 Max
	h1Max := promptUint32ForHeaderField(scanner, "Header field 1 Max (H1-max)", config.H1.Max, "32-bit random number (>= H1-min)")
	if h1Max == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}
	if h1Max < h1Min {
		h1Max = h1Min
		fmt.Printf("H1-max adjusted to H1-min: %d\n", h1Max)
	}
	config.H1 = ipn.MagicHeaderRange{Min: h1Min, Max: h1Max}

	// H2 Min
	h2Min := promptUint32ForHeaderField(scanner, "Header field 2 Min (H2-min)", config.H2.Min, "32-bit random number (0-4294967295)")
	if h2Min == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}

	// H2 Max
	h2Max := promptUint32ForHeaderField(scanner, "Header field 2 Max (H2-max)", config.H2.Max, "32-bit random number (>= H2-min)")
	if h2Max == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}
	if h2Max < h2Min {
		h2Max = h2Min
		fmt.Printf("H2-max adjusted to H2-min: %d\n", h2Max)
	}
	config.H2 = ipn.MagicHeaderRange{Min: h2Min, Max: h2Max}

	// H3 Min
	h3Min := promptUint32ForHeaderField(scanner, "Header field 3 Min (H3-min)", config.H3.Min, "32-bit random number (0-4294967295)")
	if h3Min == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}

	// H3 Max
	h3Max := promptUint32ForHeaderField(scanner, "Header field 3 Max (H3-max)", config.H3.Max, "32-bit random number (>= H3-min)")
	if h3Max == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}
	if h3Max < h3Min {
		h3Max = h3Min
		fmt.Printf("H3-max adjusted to H3-min: %d\n", h3Max)
	}
	config.H3 = ipn.MagicHeaderRange{Min: h3Min, Max: h3Max}

	// H4 Min
	h4Min := promptUint32ForHeaderField(scanner, "Header field 4 Min (H4-min)", config.H4.Min, "32-bit random number (0-4294967295)")
	if h4Min == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}

	// H4 Max
	h4Max := promptUint32ForHeaderField(scanner, "Header field 4 Max (H4-max)", config.H4.Max, "32-bit random number (>= H4-min)")
	if h4Max == 0xFFFFFFFF { // Special marker for "random" input
		generateAllRandomHeaderFields(config)
		return
	}
	if h4Max < h4Min {
		h4Max = h4Min
		fmt.Printf("H4-max adjusted to H4-min: %d\n", h4Max)
	}
	config.H4 = ipn.MagicHeaderRange{Min: h4Min, Max: h4Max}
}

// promptPrefixParameters prompts for prefix parameters (S1-S4) with random support.
func promptPrefixParameters(scanner *bufio.Scanner, config *ipn.AmneziaWGPrefs) {
	printSectionHeader("Prefix Parameters (s1-s4)")
	fmt.Println("These parameters add pseudorandom prefixes to different packet types.")
	fmt.Println("💡 Tip: Enter 'random' at any prompt to auto-generate all S1-S4 values")
	fmt.Println("⚠️  If ANY node sets these values, ALL nodes in the network must use IDENTICAL values!")
	fmt.Println("👉  All-or-none: If S1 is 0 (disabled), all prefix fields will be disabled & skipped.")

	// S1
	s1 := promptUint16ForPrefixField(scanner, "Init packet prefix length (S1)", config.S1, "0-64, recommended: 1-15, breaks standard WG compatibility, MUST match all nodes")
	if s1 == 0xFFFF { // Special marker for "random" input
		generateAllRandomPrefixFields(config)
		return
	}
	if s1 == 0 {
		config.S1, config.S2, config.S3, config.S4 = 0, 0, 0, 0
		fmt.Println("S1 disabled -> Skipping all prefix fields (all disabled).")
		return
	}
	config.S1 = s1

	// S2
	s2 := promptUint16ForPrefixField(scanner, "Response packet prefix length (S2)", config.S2, "0-64, recommended: 1-15, breaks standard WG compatibility, MUST match all nodes")
	if s2 == 0xFFFF { // Special marker for "random" input
		generateAllRandomPrefixFields(config)
		return
	}
	config.S2 = s2

	// S3
	s3 := promptUint16ForPrefixField(scanner, "Cookie packet prefix length (S3)", config.S3, "0-64, recommended: 1-15, MUST match all nodes")
	if s3 == 0xFFFF { // Special marker for "random" input
		generateAllRandomPrefixFields(config)
		return
	}
	config.S3 = s3

	// S4
	s4 := promptUint16ForPrefixField(scanner, "Transport packet prefix length (S4)", config.S4, "0-64, recommended: 1-15, MUST match all nodes")
	if s4 == 0xFFFF { // Special marker for "random" input
		generateAllRandomPrefixFields(config)
		return
	}
	config.S4 = s4
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
}

// isConfigZero checks if the Amnezia-WG configuration is all zero values.
func isConfigZero(config ipn.AmneziaWGPrefs) bool {
	return config.JC == 0 && config.JMin == 0 && config.JMax == 0 &&
		config.S1 == 0 && config.S2 == 0 && config.S3 == 0 && config.S4 == 0 &&
		config.I1 == "" && config.I2 == "" && config.I3 == "" && config.I4 == "" && config.I5 == "" &&
		(config.H1.Min == 0 && config.H1.Max == 0) && (config.H2.Min == 0 && config.H2.Max == 0) &&
		(config.H3.Min == 0 && config.H3.Max == 0) && (config.H4.Min == 0 && config.H4.Max == 0)
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

func promptMagicHeaderRangeWithHint(scanner *bufio.Scanner, prompt string, current ipn.MagicHeaderRange, hint string) ipn.MagicHeaderRange {
	var displayValue string
	if current.Min == 0 && current.Max == 0 {
		displayValue = "0 (disabled)"
	} else if current.Min == current.Max {
		displayValue = fmt.Sprintf("%d", current.Min)
	} else {
		displayValue = fmt.Sprintf("%d-%d", current.Min, current.Max)
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
		// Generate two random 32-bit numbers for a range
		rand1 := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
		// Use a different approach for second random to ensure different values
		rand2 := uint32(((time.Now().UnixNano() >> 16) ^ 0x5A5A5A5A) & 0xFFFFFFFF)

		// Ensure min <= max
		var min, max uint32
		if rand1 <= rand2 {
			min, max = rand1, rand2
		} else {
			min, max = rand2, rand1
		}

		// If by chance they're the same, adjust max
		if min == max && max < 0xFFFFFFFF {
			max++
		} else if min == max && max == 0xFFFFFFFF {
			min--
		}

		fmt.Printf("Generated random range: %d-%d\n", min, max)
		return ipn.MagicHeaderRange{Min: min, Max: max}
	}

	if strings.ToLower(text) == "random-single" {
		// Generate a single random 32-bit number
		randomValue := uint32(time.Now().UnixNano() & 0xFFFFFFFF)
		fmt.Printf("Generated random single value: %d\n", randomValue)
		return ipn.MagicHeaderRange{Min: randomValue, Max: randomValue}
	}

	// Parse range format "min-max" or single value
	parts := strings.SplitN(text, "-", 2)
	var min, max uint64
	var err error

	if len(parts) == 2 {
		min, err = strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			fmt.Printf("Invalid min value '%s', keeping current: %s\n", parts[0], displayValue)
			return current
		}
		max, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			fmt.Printf("Invalid max value '%s', keeping current: %s\n", parts[1], displayValue)
			return current
		}
		if min > max {
			fmt.Printf("Min (%d) cannot be greater than max (%d), keeping current: %s\n", min, max, displayValue)
			return current
		}
	} else {
		min, err = strconv.ParseUint(text, 10, 32)
		if err != nil {
			fmt.Printf("Invalid value '%s', keeping current: %s\n", text, displayValue)
			fmt.Println("Tip: Enter 'random' for random range, 'random-single' for single value, or use range format like '100-200'")
			return current
		}
		max = min
	}

	return ipn.MagicHeaderRange{Min: uint32(min), Max: uint32(max)}
}

// promptUint32ForHeaderField prompts for a single uint32 header field value with "random" support.
// Returns 0xFFFFFFFF as a special marker when user enters "random".
func promptUint32ForHeaderField(scanner *bufio.Scanner, prompt string, current uint32, hint string) uint32 {
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
		return 0xFFFFFFFF // Special marker for "random" input
	}

	if val, err := strconv.ParseUint(text, 10, 32); err == nil {
		return uint32(val)
	}

	fmt.Printf("Invalid value '%s', keeping current: %d\n", text, current)
	fmt.Println("Tip: Enter 'random' to auto-generate all H1-H4 min/max values")
	return current
}

// generateRandomAWGConfig generates a complete random Amnezia-WG configuration with sensible defaults.
// Generates JC (2-6), JMin/JMax (recommended ranges), S1-S4, and H1-H4 parameters.
// Does not generate I1-I5 signature parameters as they are user-defined.
func generateRandomAWGConfig() ipn.AmneziaWGPrefs {
	baseTime := time.Now().UnixNano()

	// Generate JC between 2-6
	jc := uint16((baseTime % 5) + 2) // 2-6

	// Generate JMin and JMax in recommended ranges
	// JMin: 64-128, JMax: 128-256, ensure JMax >= JMin
	jminBase := uint16(64 + ((baseTime >> 8) % 65))    // 64-128
	jmaxBase := uint16(128 + ((baseTime >> 16) % 129)) // 128-256
	if jmaxBase < jminBase {
		jmaxBase = jminBase + uint16((baseTime>>24)%64) // ensure JMax >= JMin
	}

	config := ipn.AmneziaWGPrefs{
		JC:   jc,
		JMin: jminBase,
		JMax: jmaxBase,
	}

	// Generate random S1-S4 values (1-15)
	generateAllRandomPrefixFields(&config)

	// Generate random H1-H4 values
	generateAllRandomHeaderFields(&config)

	// I1-I5 remain empty (user-defined)

	fmt.Printf("Generated random AWG configuration:\n")
	fmt.Printf("  JC=%d, JMin=%d, JMax=%d\n", config.JC, config.JMin, config.JMax)
	fmt.Printf("  S1=%d, S2=%d, S3=%d, S4=%d\n", config.S1, config.S2, config.S3, config.S4)
	fmt.Printf("  H1=%d-%d, H2=%d-%d, H3=%d-%d, H4=%d-%d\n",
		config.H1.Min, config.H1.Max, config.H2.Min, config.H2.Max,
		config.H3.Min, config.H3.Max, config.H4.Min, config.H4.Max)
	fmt.Printf("  I1-I5: (empty - user-defined)\n")

	return config
}

// generateAllRandomHeaderFields generates random min/max values for all H1-H4 header fields.
// Ensures all ranges are non-overlapping as required by WireGuard-go.
func generateAllRandomHeaderFields(config *ipn.AmneziaWGPrefs) {
	fmt.Println("Generating random values for all H1-H4 header fields...")

	// Total range: 5 to 0xFFFFFFFF (avoiding 0-4 for compatibility)
	// Divide into 4 non-overlapping segments to prevent range conflicts
	const totalRange = uint64(0xFFFFFFFF - 4) // 4294967291
	const segmentSize = totalRange / 4        // ~1073741822 per segment
	const baseValue = uint64(5)

	// Use better randomness with multiple seeds
	seed := time.Now().UnixNano()

	// Segment 1: H1 range [5, ~1073741827]
	h1Start := baseValue
	h1End := h1Start + segmentSize
	h1Min := uint32(h1Start + uint64((seed^0x12345678)%int64(segmentSize/2)))
	h1Max := h1Min + uint32((seed^0x87654321)%(int64(h1End)-int64(h1Min)))

	// Segment 2: H2 range [~1073741828, ~2147483649]
	h2Start := h1End + 1
	h2End := h2Start + segmentSize
	h2Min := uint32(h2Start + uint64((seed^0xABCDEF00)%int64(segmentSize/2)))
	h2Max := h2Min + uint32((seed^0x00FEDCBA)%(int64(h2End)-int64(h2Min)))

	// Segment 3: H3 range [~2147483650, ~3221225471]
	h3Start := h2End + 1
	h3End := h3Start + segmentSize
	h3Min := uint32(h3Start + uint64((seed^0x13579BDF)%int64(segmentSize/2)))
	h3Max := h3Min + uint32((seed^0xFDB97531)%(int64(h3End)-int64(h3Min)))

	// Segment 4: H4 range [~3221225472, 0xFFFFFFFF]
	h4Start := h3End + 1
	h4End := baseValue + totalRange
	h4Min := uint32(h4Start + uint64((seed^0x2468ACE0)%int64(segmentSize/2)))
	h4Max := h4Min + uint32((seed^0x0ECA8642)%(int64(h4End)-int64(h4Min)))

	config.H1 = ipn.MagicHeaderRange{Min: h1Min, Max: h1Max}
	config.H2 = ipn.MagicHeaderRange{Min: h2Min, Max: h2Max}
	config.H3 = ipn.MagicHeaderRange{Min: h3Min, Max: h3Max}
	config.H4 = ipn.MagicHeaderRange{Min: h4Min, Max: h4Max}

	fmt.Printf("Generated values (non-overlapping ranges):\n")
	fmt.Printf("  H1: %d-%d (segment 1)\n", h1Min, h1Max)
	fmt.Printf("  H2: %d-%d (segment 2)\n", h2Min, h2Max)
	fmt.Printf("  H3: %d-%d (segment 3)\n", h3Min, h3Max)
	fmt.Printf("  H4: %d-%d (segment 4)\n", h4Min, h4Max)
}

// promptUint16ForPrefixField prompts for a single uint16 prefix field value with "random" support.
// Returns 0xFFFF as a special marker when user enters "random".
func promptUint16ForPrefixField(scanner *bufio.Scanner, prompt string, current uint16, hint string) uint16 {
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
		return 0xFFFF // Special marker for "random" input
	}

	if val, err := strconv.ParseUint(text, 10, 16); err == nil {
		result := uint16(val)
		if result > 64 {
			fmt.Printf("Warning: Value %d is outside recommended range (0-64), but continuing...\n", result)
		}
		return result
	}

	fmt.Printf("Invalid value '%s', keeping current: %d\n", text, current)
	fmt.Println("Tip: Enter 'random' to auto-generate all S1-S4 values")
	return current
}

// generateAllRandomPrefixFields generates random values for all S1-S4 prefix fields.
func generateAllRandomPrefixFields(config *ipn.AmneziaWGPrefs) {
	fmt.Println("Generating random values for all S1-S4 prefix fields...")

	// Generate random values in the range 1-7 for all S1-S4
	baseTime := time.Now().UnixNano()

	s1 := uint16((baseTime % 7) + 1)         // 1-7
	s2 := uint16(((baseTime >> 8) % 7) + 1)  // 1-7
	s3 := uint16(((baseTime >> 16) % 7) + 1) // 1-7
	s4 := uint16(((baseTime >> 24) % 7) + 1) // 1-7

	config.S1 = s1
	config.S2 = s2
	config.S3 = s3
	config.S4 = s4

	fmt.Printf("Generated values:\n")
	fmt.Printf("  S1: %d\n", s1)
	fmt.Printf("  S2: %d\n", s2)
	fmt.Printf("  S3: %d\n", s3)
	fmt.Printf("  S4: %d\n", s4)
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
	hasHeader := (config.H1.Min != 0 || config.H1.Max != 0) || (config.H2.Min != 0 || config.H2.Max != 0) ||
		(config.H3.Min != 0 || config.H3.Max != 0) || (config.H4.Min != 0 || config.H4.Max != 0)
	hasSignature := config.I1 != "" || config.I2 != "" || config.I3 != "" || config.I4 != "" || config.I5 != ""
	hasJunk := config.JC != 0 || config.JMin != 0 || config.JMax != 0
	hasPrefix := config.S1 != 0 || config.S2 != 0 || config.S3 != 0 || config.S4 != 0

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

	if hasHeader && (config.H1.Min > 0 || config.H1.Max > 0) && (config.H1.Min < 1000000 && config.H1.Max < 1000000) {
		fmt.Printf("💡 Note: H1-H4 should use 32-bit random numbers for better obfuscation\n   Consider using larger random values (e.g., 3847291638)\n")
	}

	fmt.Printf("\n🚨 CRITICAL NETWORK REQUIREMENT:\n   These parameters MUST be IDENTICAL on ALL nodes: H1-H4, S1-S4\n   These parameters CAN differ between nodes: I1-I5, JC/JMin/JMax\n\n")
	fmt.Printf("📋 Required Actions for H1-H4 and S1-S4:\n   1. Get values: tailscale amnezia-wg get\n   2. Apply on all nodes: tailscale amnezia-wg set\n   3. Restart tailscaled on ALL nodes\n   4. Test connectivity\n\n")
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
