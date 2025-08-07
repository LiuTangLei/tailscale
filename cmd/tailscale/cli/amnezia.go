// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
)

var amneziaCmd = &ffcli.Command{
	Name:       "amnezia-wg",
	ShortUsage: "tailscale amnezia-wg [subcommand]",
	ShortHelp:  "Configure Amnezia-WG parameters",
	LongHelp: `"tailscale amnezia-wg" allows configuring Amnezia-WG parameters.
Amnezia-WG is backward compatible with standard WireGuard when all parameters are zero.`,
	Subcommands: []*ffcli.Command{
		{
			Name:       "set",
			ShortUsage: "tailscale amnezia-wg set [json-string]",
			ShortHelp:  "Set Amnezia-WG parameters with optional restart",
			LongHelp: `Set Amnezia-WG parameters either from JSON string or interactively.
After applying changes, you will be prompted to restart tailscaled.

Examples:
  # Set from JSON
  tailscale amnezia-wg set '{"jc":5,"jmin":50,"jmax":1000,"s1":30,"s2":40,"h1":123456,"h2":67543,"h3":32345,"h4":123123}'

  # Interactive configuration
  tailscale amnezia-wg set`,
			Exec: runAmneziaWGSet,
		},
		{
			Name:       "get",
			ShortUsage: "tailscale amnezia-wg get",
			ShortHelp:  "Get current Amnezia-WG parameters",
			Exec:       runAmneziaWGGet,
		},
		{
			Name:       "reset",
			ShortUsage: "tailscale amnezia-wg reset",
			ShortHelp:  "Reset to standard WireGuard with optional restart",
			LongHelp: `Reset all Amnezia-WG parameters to zero (standard WireGuard).
After resetting, you will be prompted to restart tailscaled.`,
			Exec:       runAmneziaWGReset,
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

		fmt.Println("Configure Amnezia-WG parameters (press Enter to keep current value, 0 to disable):")

		scanner := bufio.NewScanner(os.Stdin)

		config.JC = promptUint16(scanner, "Junk packet count (jc)", config.JC)
		config.JMin = promptUint16(scanner, "Min junk size (jmin)", config.JMin)
		config.JMax = promptUint16(scanner, "Max junk size (jmax)", config.JMax)
		config.S1 = promptUint16(scanner, "Init packet junk size (s1)", config.S1)
		config.S2 = promptUint16(scanner, "Response packet junk size (s2)", config.S2)
		config.H1 = promptUint32(scanner, "Init packet magic header (h1)", config.H1)
		config.H2 = promptUint32(scanner, "Response packet magic header (h2)", config.H2)
		config.H3 = promptUint32(scanner, "Underload packet magic header (h3)", config.H3)
		config.H4 = promptUint32(scanner, "Transport packet magic header (h4)", config.H4)
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
	fmt.Printf("  S1 (init packet junk size): %d\n", config.S1)
	fmt.Printf("  S2 (response packet junk size): %d\n", config.S2)
	fmt.Printf("  H1 (init packet magic header): %d\n", config.H1)
	fmt.Printf("  H2 (response packet magic header): %d\n", config.H2)
	fmt.Printf("  H3 (underload packet magic header): %d\n", config.H3)
	fmt.Printf("  H4 (transport packet magic header): %d\n", config.H4)

	// Print as JSON for easy copy-paste
	jsonBytes, err := json.Marshal(config)
	if err == nil && (config != ipn.AmneziaWGPrefs{}) {
		fmt.Printf("\nJSON format:\n%s\n", string(jsonBytes))
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
