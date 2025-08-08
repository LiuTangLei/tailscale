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
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
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
  tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70}'

  # Advanced protocol masking with captured protocol header
  tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70,"s1":10,"s2":15,"i1":"<b 0xc0000000><c><t>"}'

  # Header field parameters with junk packets
  tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70,"h1":3847291638,"h2":1029384756,"h3":2847291047,"h4":3918472658}'

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

func runAmneziaWGSet(ctx context.Context, args []string) error {
	var config ipn.AmneziaWGPrefs

	if len(args) == 1 {
		// Parse JSON argument
		if err := json.Unmarshal([]byte(args[0]), &config); err != nil {
			return fmt.Errorf("invalid JSON: %v", err)
		}
	} else if len(args) == 0 {
		// Interactive configuration
		curPrefs, err := localClient.GetPrefs(ctx)
		if err != nil {
			return err
		}
		config = curPrefs.AmneziaWG

		fmt.Println("Configure Amnezia-WG parameters (press Enter to keep current value, 0 or empty to disable):")
		fmt.Println("⚠️  H1-H4 and S1/S2 must be IDENTICAL on all nodes. I1-I5, JC, JMin, JMax can differ.")
		fmt.Println("Tip: For maximum compatibility, use junk packets only. For advanced DPI evasion, add CPS signatures.\n")

		scanner := bufio.NewScanner(os.Stdin)

		config.JC = promptUint16WithRange(scanner, "Junk packet count", config.JC, "0-10", "Recommended: 3-6 for basic DPI evasion")
		config.JMin = promptUint16WithRange(scanner, "Min junk packet size (bytes)", config.JMin, "64-1024", "Recommended: 40-50, must be ≤ jmax")
		config.JMax = promptUint16WithRange(scanner, "Max junk packet size (bytes)", config.JMax, "64-1024", "Recommended: 70-100, must be ≥ jmin")
		config.S1 = promptUint16WithRange(scanner, "Init packet prefix length (S1)", config.S1, "0-64", "Recommended: 10-20, breaks standard WG compatibility, MUST match all nodes")
		config.S2 = promptUint16WithRange(scanner, "Response packet prefix length (S2)", config.S2, "0-64", "Recommended: 10-20, breaks standard WG compatibility, MUST match all nodes")

		fmt.Println("\n" + strings.Repeat("=", 70))
		fmt.Println("Header Field Parameters (h1-h4)")
		fmt.Println(strings.Repeat("=", 70))
		fmt.Println("These parameters provide basic protocol obfuscation using 32-bit random values.")
		fmt.Println("Use random numbers (0-4294967295) for effective obfuscation.")
		fmt.Println("💡 Tip: Enter 'random' to auto-generate a 32-bit random number")
		fmt.Println("⚠️  If ANY node sets these values, ALL nodes in the network must use IDENTICAL values!")
		fmt.Println()

		config.H1 = promptUint32WithHint(scanner, "Header field 1 (H1)", config.H1, "32-bit random number (0-4294967295)")
		config.H2 = promptUint32WithHint(scanner, "Header field 2 (H2)", config.H2, "32-bit random number (0-4294967295)")
		config.H3 = promptUint32WithHint(scanner, "Header field 3 (H3)", config.H3, "32-bit random number (0-4294967295)")
		config.H4 = promptUint32WithHint(scanner, "Header field 4 (H4)", config.H4, "32-bit random number (0-4294967295)")

		fmt.Println("\n" + strings.Repeat("=", 70))
		fmt.Println("Custom Protocol Signature (CPS) Packets - Advanced Protocol Masking")
		fmt.Println(strings.Repeat("=", 70))
		fmt.Println("Format: <b hex_data> | <c> (counter) | <t> (timestamp) | <r length> (random)")
		fmt.Println("Note: If I1 is empty, signature chain (I2-I5) is skipped")
		fmt.Println("\nTo create effective CPS signatures:")
		fmt.Println("1. Capture real protocol packets with Wireshark or tcpdump")
		fmt.Println("2. Extract hex patterns from packet headers")
		fmt.Println("3. Use <b hex_pattern> for static protocol headers")
		fmt.Println("4. Add <c>, <t>, <r length> for dynamic fields")
		fmt.Println("")
		fmt.Println("📖 Complete guide: https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted")
		fmt.Println("")
		fmt.Println("💡 For long CPS signatures (real packet captures), use JSON mode:")
		fmt.Println("   tailscale amnezia-wg set '{\"i1\":\"<b 0x...very_long_hex...>\"}'")
		fmt.Println("")
		fmt.Println("Basic format examples:")
		fmt.Println("  Static header only:     <b 0xc0000000>")
		fmt.Println("  With random padding:    <b 0x1234><r 16>")
		fmt.Println("  With counter+timestamp: <b 0xabcd><c><t>")
		fmt.Println()
		fmt.Println("⚠️  Terminal Input Limitation:")
		fmt.Println("  For long CPS signatures (>1000 chars), terminal input may be truncated.")
		fmt.Println("  Use JSON mode instead: tailscale amnezia-wg set '{\"i1\":\"<your_long_cps>\"}'")
		fmt.Println()

		config.I1 = promptStringWithExample(scanner, "Primary signature packet (I1)", config.I1, "Leave empty for standard WireGuard compatibility (use JSON for long signatures >1000 chars)")
		if config.I1 != "" {
			config.I2 = promptStringWithExample(scanner, "Secondary signature packet (I2)", config.I2, "Optional entropy packet (use JSON for long signatures)")
			config.I3 = promptStringWithExample(scanner, "Tertiary signature packet (I3)", config.I3, "Optional entropy packet (use JSON for long signatures)")
			config.I4 = promptStringWithExample(scanner, "Quaternary signature packet (I4)", config.I4, "Optional entropy packet (use JSON for long signatures)")
			config.I5 = promptStringWithExample(scanner, "Quinary signature packet (I5)", config.I5, "Optional entropy packet (use JSON for long signatures)")
		} else {
			fmt.Println("Skipping I2-I5 (I1 is empty - standard WireGuard compatibility mode)")
		}
	} else {
		return fmt.Errorf("usage: tailscale amnezia-wg set [json-string]")
	}

	// Apply the configuration
	maskedPrefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AmneziaWG: config,
		},
		AmneziaWGSet: true,
	}

	_, err := localClient.EditPrefs(ctx, maskedPrefs)
	if err != nil {
		return err
	}

	fmt.Println("Amnezia-WG configuration updated successfully.")

	// Ask user if they want to restart tailscaled
	fmt.Print("Restart tailscaled now to apply changes? [Y/n]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		response := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if response == "" || response == "y" || response == "yes" {
			fmt.Println("Restarting tailscaled...")
			if err := restartTailscaled(); err != nil {
				fmt.Printf("Warning: Failed to restart tailscaled: %v\n", err)
				fmt.Println("You may need to restart tailscaled manually for changes to take effect.")
			} else {
				fmt.Println("tailscaled restarted successfully.")
			}
		} else {
			fmt.Println("Skipped restart. Please restart tailscaled manually for changes to take effect.")
		}
	}

	return nil
}

func runAmneziaWGGet(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: tailscale amnezia-wg get")
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	config := prefs.AmneziaWG
	fmt.Printf("Current Amnezia-WG configuration:\n")
	fmt.Printf("  JC (junk packet count): %d\n", config.JC)
	fmt.Printf("  JMin (min junk size): %d\n", config.JMin)
	fmt.Printf("  JMax (max junk size): %d\n", config.JMax)
	fmt.Printf("  S1 (init packet prefix length): %d\n", config.S1)
	fmt.Printf("  S2 (response packet prefix length): %d\n", config.S2)
	fmt.Printf("  I1 (primary signature packet): %s\n", config.I1)
	fmt.Printf("  I2 (secondary signature packet): %s\n", config.I2)
	fmt.Printf("  I3 (tertiary signature packet): %s\n", config.I3)
	fmt.Printf("  I4 (quaternary signature packet): %s\n", config.I4)
	fmt.Printf("  I5 (quinary signature packet): %s\n", config.I5)
	fmt.Printf("  H1 (header field 1): %d\n", config.H1)
	fmt.Printf("  H2 (header field 2): %d\n", config.H2)
	fmt.Printf("  H3 (header field 3): %d\n", config.H3)
	fmt.Printf("  H4 (header field 4): %d\n", config.H4)

	// Print as JSON for easy copy-paste
	isZero := config.JC == 0 && config.JMin == 0 && config.JMax == 0 &&
		config.S1 == 0 && config.S2 == 0 &&
		config.I1 == "" && config.I2 == "" && config.I3 == "" && config.I4 == "" && config.I5 == "" &&
		config.H1 == 0 && config.H2 == 0 && config.H3 == 0 && config.H4 == 0

	if !isZero {
		var buf bytes.Buffer
		encoder := json.NewEncoder(&buf)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "")
		if err := encoder.Encode(config); err == nil {
			// Remove the trailing newline that Encode adds
			jsonStr := strings.TrimRight(buf.String(), "\n")
			fmt.Printf("\nJSON format:\n%s\n", jsonStr)
		}
	}

	return nil
}

func runAmneziaWGReset(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: tailscale amnezia-wg reset")
	}

	// Reset to all zeros (standard WireGuard)
	maskedPrefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AmneziaWG: ipn.AmneziaWGPrefs{}, // All zero values
		},
		AmneziaWGSet: true,
	}

	_, err := localClient.EditPrefs(ctx, maskedPrefs)
	if err != nil {
		return err
	}

	fmt.Println("Amnezia-WG configuration reset to standard WireGuard.")

	// Ask user if they want to restart tailscaled
	fmt.Print("Restart tailscaled now to apply changes? [Y/n]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		response := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if response == "" || response == "y" || response == "yes" {
			fmt.Println("Restarting tailscaled...")
			if err := restartTailscaled(); err != nil {
				fmt.Printf("Warning: Failed to restart tailscaled: %v\n", err)
				fmt.Println("You may need to restart tailscaled manually for changes to take effect.")
			} else {
				fmt.Println("tailscaled restarted successfully.")
			}
		} else {
			fmt.Println("Skipped restart. Please restart tailscaled manually for changes to take effect.")
		}
	}

	return nil
}

func promptUint16(scanner *bufio.Scanner, prompt string, current uint16) uint16 {
	fmt.Printf("%s [%d]: ", prompt, current)
	if !scanner.Scan() {
		return current
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return current
	}
	if val, err := strconv.ParseUint(text, 10, 16); err == nil {
		return uint16(val)
	}
	fmt.Printf("Invalid value, keeping current: %d\n", current)
	return current
}

func promptUint32(scanner *bufio.Scanner, prompt string, current uint32) uint32 {
	fmt.Printf("%s [%d]: ", prompt, current)
	if !scanner.Scan() {
		return current
	}
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return current
	}
	if val, err := strconv.ParseUint(text, 10, 32); err == nil {
		return uint32(val)
	}
	fmt.Printf("Invalid value, keeping current: %d\n", current)
	return current
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
	displayValue := current
	if displayValue == "" {
		displayValue = "(empty)"
	}
	fmt.Printf("%s [%s]: ", prompt, displayValue)
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
	displayValue := fmt.Sprintf("%d", current)
	if current == 0 {
		displayValue = "0 (disabled)"
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

	if val, err := strconv.ParseUint(text, 10, 16); err == nil {
		result := uint16(val)
		// Validate ranges based on official documentation
		switch {
		case strings.Contains(prompt, "Junk packet count") && result > 10:
			fmt.Printf("Warning: Value %d exceeds recommended range (0-10), but continuing...\n", result)
		case strings.Contains(prompt, "junk packet size") && result > 0 && (result < 64 || result > 1024):
			fmt.Printf("Warning: Value %d is outside recommended range (64-1024), but continuing...\n", result)
		case (strings.Contains(prompt, "prefix length")) && result > 64:
			fmt.Printf("Warning: Value %d exceeds maximum (64), but continuing...\n", result)
		}
		return result
	}

	fmt.Printf("Invalid value '%s', keeping current: %d\n", text, current)
	return current
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

func runAmneziaWGValidate(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: tailscale amnezia-wg validate")
	}

	prefs, err := localClient.GetPrefs(ctx)
	if err != nil {
		return err
	}

	config := prefs.AmneziaWG
	fmt.Println("Amnezia-WG Configuration Validation")
	fmt.Println("===================================")

	// Check if configuration is completely zero (standard WireGuard)
	isStandardWG := config.JC == 0 && config.JMin == 0 && config.JMax == 0 &&
		config.S1 == 0 && config.S2 == 0 &&
		config.I1 == "" && config.I2 == "" && config.I3 == "" && config.I4 == "" && config.I5 == "" &&
		config.H1 == 0 && config.H2 == 0 && config.H3 == 0 && config.H4 == 0

	if isStandardWG {
		fmt.Println("✅ Status: Standard WireGuard mode (all parameters disabled)")
		fmt.Println("✅ Compatibility: Full compatibility with all WireGuard clients")
		fmt.Println("✅ Network requirement: No special configuration needed on other nodes")
		return nil
	}

	// Check for mixed versions
	hasHeaderParams := config.H1 != 0 || config.H2 != 0 || config.H3 != 0 || config.H4 != 0
	hasSignatureParams := config.I1 != "" || config.I2 != "" || config.I3 != "" || config.I4 != "" || config.I5 != ""
	hasJunkParams := config.JC != 0 || config.JMin != 0 || config.JMax != 0
	hasPrefixParams := config.S1 != 0 || config.S2 != 0

	fmt.Printf("⚠️  Status: Amnezia-WG mode enabled\n")
	fmt.Printf("📊 Parameter Summary:\n")
	fmt.Printf("   - Junk packets: %s\n", formatEnabled(hasJunkParams))
	fmt.Printf("   - Prefix lengths (S1/S2): %s\n", formatEnabled(hasPrefixParams))
	fmt.Printf("   - Header parameters (H1-H4): %s\n", formatEnabled(hasHeaderParams))
	fmt.Printf("   - Signature parameters (I1-I5): %s\n", formatEnabled(hasSignatureParams))
	fmt.Printf("\n")

	// Compatibility analysis
	fmt.Printf("🔍 Compatibility Analysis:\n")

	if hasJunkParams && !hasPrefixParams && !hasHeaderParams && !hasSignatureParams {
		fmt.Printf("✅ Junk packets only: Compatible with standard WireGuard clients\n")
		fmt.Printf("✅ Low impact: Should work with most configurations\n")
	} else {
		fmt.Printf("⚠️  Protocol modification: NOT compatible with standard WireGuard\n")
		fmt.Printf("❌ Breaking changes: S1/S2, H1-H4, or I1-I5 parameters are set\n")
	}

	if hasHeaderParams && hasSignatureParams {
		fmt.Printf("⚠️  Mixed parameter types: Both header (H1-H4) and signature (I1-I5) parameters detected\n")
		fmt.Printf("💡 Recommendation: Use either header OR signature parameters, not both\n")
	}

	if hasHeaderParams {
		// Check if header values look random (basic heuristic)
		headerValues := []uint32{config.H1, config.H2, config.H3, config.H4}
		hasSmallValues := false
		for _, val := range headerValues {
			if val > 0 && val < 1000000 { // Values that look too simple
				hasSmallValues = true
				break
			}
		}
		if hasSmallValues {
			fmt.Printf("💡 Note: H1-H4 should use 32-bit random numbers for better obfuscation\n")
			fmt.Printf("   Consider using larger random values (e.g., 3847291638)\n")
		}
	}

	fmt.Printf("\n")
	fmt.Printf("🚨 CRITICAL NETWORK REQUIREMENT:\n")
	fmt.Printf("   These parameters MUST be IDENTICAL on ALL nodes:\n")
	fmt.Printf("   - H1-H4 (header fields)\n")
	fmt.Printf("   - S1/S2 (prefix lengths)\n")
	fmt.Printf("\n")
	fmt.Printf("   These parameters CAN differ between nodes:\n")
	fmt.Printf("   - I1-I5 (signature packets)\n")
	fmt.Printf("   - JC, JMin, JMax (junk packets)\n")
	fmt.Printf("\n")
	fmt.Printf("📋 Required Actions for H1-H4 and S1/S2:\n")
	fmt.Printf("   1. Copy these critical values to ALL other nodes:\n")
	fmt.Printf("      tailscale amnezia-wg get  # (note H1-H4 and S1/S2 values)\n")
	fmt.Printf("   2. Apply matching values on each node:\n")
	fmt.Printf("      tailscale amnezia-wg set  # (enter same H1-H4 and S1/S2)\n")
	fmt.Printf("   3. Restart tailscaled on ALL nodes\n")
	fmt.Printf("   4. Test connectivity between all node pairs\n")
	fmt.Printf("\n")

	// Validation warnings
	if config.JMin > 0 && config.JMax > 0 && config.JMin > config.JMax {
		fmt.Printf("❌ Error: JMin (%d) is greater than JMax (%d)\n", config.JMin, config.JMax)
	}

	if config.JC > 10 {
		fmt.Printf("⚠️  Warning: JC (%d) is very high, may impact performance\n", config.JC)
	}

	return nil
}

func formatEnabled(enabled bool) string {
	if enabled {
		return "Enabled ⚠️"
	}
	return "Disabled ✅"
}
