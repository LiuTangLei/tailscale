// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	// AWG i-packets are sent as a single UDP datagram. Keeping the generated
	// payload below 64 KiB prevents a compact CPS expression from causing an
	// unbounded allocation in the WireGuard handshake path.
	maxAmneziaIPacketBytes = 64<<10 - 1
	maxAmneziaCPSBytes     = 60 << 10
	maxAmneziaDiscoBytes   = 60 << 10

	// Junk packets are generated together for every handshake attempt. These
	// limits are deliberately far above normal AWG profiles while preventing a
	// valid uint16 configuration from allocating several gigabytes at once.
	maxAmneziaJunkPackets = 4096
	maxAmneziaJunkBytes   = 64 << 20

	zeroHeaderProtectionKey = "0000000000000000000000000000000000000000000000000000000000000000"
)

// ValidateAmneziaWGConfig validates an AWG v2 or v3 configuration before it
// reaches wireguard-go. It intentionally accepts historical scalar header
// values and all CPS tags supported by the current AmneziaWG core, while
// rejecting malformed or unsafe values that the core cannot apply safely.
func ValidateAmneziaWGConfig(p AmneziaWGPrefs) error {
	if p.JMin != 0 && p.JMax != 0 && p.JMin > p.JMax {
		return fmt.Errorf("JMin (%d) cannot be greater than JMax (%d)", p.JMin, p.JMax)
	}
	if p.JC > maxAmneziaJunkPackets {
		return fmt.Errorf("JC (%d) exceeds the safe limit of %d packets per handshake", p.JC, maxAmneziaJunkPackets)
	}
	if uint64(p.JC)*uint64(p.JMax) > maxAmneziaJunkBytes {
		return fmt.Errorf("JC and JMax request more than %d bytes of junk per handshake", maxAmneziaJunkBytes)
	}

	ranges := []struct {
		name  string
		value MagicHeaderRange
	}{
		{"H1", p.H1}, {"H2", p.H2}, {"H3", p.H3}, {"H4", p.H4},
		{"ContentPaddingAddition", p.ContentPaddingAddition},
		{"RekeyAfterTime", p.RekeyAfterTime},
		{"RekeyTimeout", p.RekeyTimeout},
		{"RejectAfterTime", p.RejectAfterTime},
		{"KeepaliveTimeout", p.KeepaliveTimeout},
		{"MaxHandshakeAttempts", p.MaxHandshakeAttempts},
	}
	for _, r := range ranges {
		if r.value.Max < r.value.Min {
			return fmt.Errorf("%s maximum (%d) cannot be less than minimum (%d)", r.name, r.value.Max, r.value.Min)
		}
	}

	// A zero header means the standard WireGuard message type. Validate those
	// effective values too, matching wireguard-go's final overlap check.
	headers := []struct {
		name  string
		value MagicHeaderRange
	}{
		{"H1", effectiveAmneziaHeader(p.H1, 1)},
		{"H2", effectiveAmneziaHeader(p.H2, 2)},
		{"H3", effectiveAmneziaHeader(p.H3, 3)},
		{"H4", effectiveAmneziaHeader(p.H4, 4)},
	}
	for i := range headers {
		for j := i + 1; j < len(headers); j++ {
			if amneziaRangesOverlap(headers[i].value, headers[j].value) {
				return fmt.Errorf("%s (%s) overlaps %s (%s)", headers[i].name, headers[i].value, headers[j].name, headers[j].value)
			}
		}
	}

	for _, signature := range []struct {
		name, value string
	}{
		{"I1", p.I1}, {"I2", p.I2}, {"I3", p.I3}, {"I4", p.I4}, {"I5", p.I5},
	} {
		if err := validateAmneziaCPS(signature.value); err != nil {
			if strings.HasPrefix(err.Error(), "contains the retired CPS tag") {
				return fmt.Errorf("%s %w", signature.name, err)
			}
			return fmt.Errorf("%s: %w", signature.name, err)
		}
	}

	if p.HeaderProtectionKey != "" {
		key, err := hex.DecodeString(p.HeaderProtectionKey)
		if err != nil || len(key) != 32 {
			return fmt.Errorf("HeaderProtectionKey must contain exactly 64 hexadecimal characters")
		}
		allZero := true
		for _, b := range key {
			allZero = allZero && b == 0
		}
		if !allZero {
			for i, padding := range []uint16{p.S1, p.S2, p.S3, p.S4} {
				if padding < 12 {
					return fmt.Errorf("S%d must be at least 12 when HeaderProtectionKey is enabled", i+1)
				}
			}
		}
	}

	_, err := MarshalAmneziaWGConfigForDisco(p)
	return err
}

// MarshalAmneziaWGConfigForDisco encodes p for the AWG disco response and
// enforces the transport limit used by every peer. HTML escaping is disabled
// because CPS expressions commonly contain angle brackets; escaping them
// would needlessly expand an otherwise valid profile on the wire.
//
// This function only validates the serialized size. Call
// [ValidateAmneziaWGConfig] before accepting an untrusted profile.
func MarshalAmneziaWGConfigForDisco(p AmneziaWGPrefs) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		return nil, fmt.Errorf("encode Amnezia-WG config for disco: %w", err)
	}
	encoded := bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
	if len(encoded) > maxAmneziaDiscoBytes {
		return nil, fmt.Errorf("serialized Amnezia-WG config is %d bytes, exceeding the disco limit of %d", len(encoded), maxAmneziaDiscoBytes)
	}
	return encoded, nil
}

func effectiveAmneziaHeader(value MagicHeaderRange, standard uint32) MagicHeaderRange {
	if value.IsZero() {
		return MagicHeaderRange{Min: standard, Max: standard}
	}
	return value
}

func amneziaRangesOverlap(a, b MagicHeaderRange) bool {
	return a.Min <= b.Max && b.Min <= a.Max
}

// validateAmneziaCPS validates the CPS grammar used for I1-I5 and calculates
// its fixed output size for an i-packet (whose input is empty). The parser
// intentionally mirrors wireguard-go by using the first argument and ignoring
// later arguments, preserving profiles produced by older tools.
func validateAmneziaCPS(spec string) error {
	if spec == "" {
		return nil
	}
	if len(spec) > maxAmneziaCPSBytes {
		return fmt.Errorf("CPS expression exceeds %d bytes", maxAmneziaCPSBytes)
	}
	for _, b := range []byte(spec) {
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("CPS expression contains a control character")
		}
	}

	remaining := spec
	outputBytes := int64(0)
	for remaining != "" {
		start := strings.IndexByte(remaining, '<')
		if start < 0 {
			if strings.TrimSpace(remaining) != "" {
				return fmt.Errorf("unexpected text outside CPS tags")
			}
			break
		}
		if strings.TrimSpace(remaining[:start]) != "" {
			return fmt.Errorf("unexpected text outside CPS tags")
		}
		end := strings.IndexByte(remaining[start+1:], '>')
		if end < 0 {
			return fmt.Errorf("missing enclosing >")
		}
		end += start + 1
		fields := strings.Fields(remaining[start+1 : end])
		if len(fields) == 0 {
			return fmt.Errorf("empty CPS tag")
		}
		tag := fields[0]
		arg := ""
		if len(fields) > 1 {
			arg = fields[1]
		}

		tagOutputBytes := int64(0)
		switch tag {
		case "b":
			value := strings.TrimPrefix(arg, "0x")
			if value == "" {
				return fmt.Errorf("tag <b> requires a non-empty hexadecimal argument")
			}
			if len(value)%2 != 0 {
				return fmt.Errorf("tag <b> contains an odd number of hexadecimal characters")
			}
			if _, err := hex.DecodeString(value); err != nil {
				return fmt.Errorf("tag <b> contains invalid hexadecimal data: %w", err)
			}
			tagOutputBytes = int64(len(value) / 2)
		case "t":
			tagOutputBytes = 4
		case "r", "rc", "rd", "dz":
			length, err := strconv.ParseInt(arg, 10, 64)
			if err != nil {
				return fmt.Errorf("tag <%s> requires an integer length: %w", tag, err)
			}
			if length < 0 {
				return fmt.Errorf("tag <%s> length cannot be negative", tag)
			}
			tagOutputBytes = length
		case "d", "ds":
			// I1-I5 are generated from an empty input, so these tags add no
			// fixed bytes. They remain accepted for upstream compatibility.
		case "c":
			return fmt.Errorf("contains the retired CPS tag <c>; AmneziaWG 2.0 removed this packet counter, so remove <c> and keep the remaining tags")
		default:
			return fmt.Errorf("unknown CPS tag <%s>", tag)
		}
		if err := addAmneziaCPSOutputBytes(&outputBytes, tagOutputBytes); err != nil {
			return err
		}
		remaining = remaining[end+1:]
	}
	return nil
}

// addAmneziaCPSOutputBytes adds a tag's fixed output size without allowing the
// int64 accumulator to overflow before the i-packet size limit is checked.
func addAmneziaCPSOutputBytes(outputBytes *int64, tagOutputBytes int64) error {
	const maxOutputBytes = int64(maxAmneziaIPacketBytes)
	if tagOutputBytes < 0 {
		return fmt.Errorf("CPS tag output length cannot be negative")
	}
	if *outputBytes < 0 || *outputBytes > maxOutputBytes || tagOutputBytes > maxOutputBytes-*outputBytes {
		return fmt.Errorf("CPS expression output exceeds the safe limit of %d bytes", maxAmneziaIPacketBytes)
	}
	*outputBytes += tagOutputBytes
	return nil
}
