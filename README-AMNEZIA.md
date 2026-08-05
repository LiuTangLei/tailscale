# Tailscale with AmneziaWG v2 and v3 Integration

A Tailscale fork that integrates both legacy AWG v2 profiles and AWG v3 profiles while preserving standard WireGuard behavior when every AWG field is disabled.

The concise command is `tailscale awg`. The historical `tailscale amnezia-wg`
name remains available as a compatibility alias for existing scripts.

## Key Features

- **Zero-config compatibility**: Behaves exactly like standard Tailscale by default
- **CLI configuration**: Change settings from the CLI and get platform-specific restart guidance when transport parameters need to be rebuilt
- **Multiple interfaces**: CLI commands, JSON flags, and environment variables
- **Advanced DPI evasion**: Custom Protocol Signature (CPS), junk packet injection, and handshake randomization
- **Protocol masking**: Mimic QUIC, DNS, SIP, and other UDP protocols
- **Dynamic headers**: Randomized packet headers make each client unique
- **AWG v3**: Header protection, transport content padding, and configurable handshake/keepalive timing ranges
- **v3-to-v2 fallback**: Applying or syncing a v2 profile clears every v3-only device setting
- **Mobile LocalAPI compatibility**: Existing Android/iOS AWG sync and preference JSON fields remain unchanged
- **Deterministic peer sync**: Requests bind both NodeKey and DiscoKey, including when peers share a DiscoKey
- **Backward compatible**: All zero/empty values = standard WireGuard behavior
- **AmneziaWG 1.0 compatibility**: When I1 is empty, behaves like AmneziaWG 1.0

## Quick Start

### Basic DPI Evasion (Recommended)

```bash
# Add junk packets for basic DPI evasion (prompt to restart)
tailscale awg set '{"jc":4,"jmin":40,"jmax":70}'

# Advanced protocol masking with QUIC-like signature
tailscale awg set '{"jc":4,"jmin":40,"jmax":70,"s1":10,"s2":15,"i1":"<b 0xc0><r 32><t>"}'

# AWG v3 (HeaderProtectionKey requires S1-S4 >= 12)
tailscale awg set '{"jc":5,"jmin":500,"jmax":1000,"s1":15,"s2":18,"s3":20,"s4":25,"h1":"123456-123500","h2":"67543-67550","h3":"123123-123200","h4":"32345-32350","header_protection_key":"4242424242424242424242424242424242424242424242424242424242424242","content_padding_addition":"5-31","rekey_after_time":"120-180","rekey_timeout":"5-7","reject_after_time":"180-240","keepalive_timeout":"10-15","max_handshake_attempts":"8-12"}'

# Verify configuration
tailscale awg get

# Discover and copy a profile from an online peer
tailscale awg sync

# Reset to standard WireGuard (prompt to restart)
tailscale awg reset
```

### Alternative Configuration Methods

```bash
# Via set command with JSON flag
tailscale set --amnezia-wg='{"jc":4,"jmin":40,"jmax":70}'

# Interactive generator: press Enter for AWG v3, or choose 2 for legacy AWG v2
tailscale awg set
# The generated JSON is shown before it is applied.

# Environment variables (requires tailscaled restart)
export TS_AMNEZIA_JC=4 TS_AMNEZIA_JMIN=40 TS_AMNEZIA_JMAX=70
export TS_AMNEZIA_I1='<b 0xc0><r 32><t>'
sudo systemctl restart tailscaled
```

Environment variables are legacy daemon overlays: each one is used while the
corresponding stored preference is zero/empty. `awg sync` advertises the
effective runtime profile, while `awg get` shows stored preferences. Therefore,
`awg reset` cannot disable a non-zero `TS_AMNEZIA_*` value; unset it and restart
tailscaled (or the container) as well.

### Restarting After AWG Changes

Most Linux installs use systemd:

```bash
sudo systemctl restart tailscaled
```

OpenWrt uses the `tailscale` init service name:

```sh
/etc/init.d/tailscale restart
```

Docker and Kubernetes images usually run `tailscaled` under `containerboot`, without an in-container service manager. Restart the container or pod from the host/orchestrator instead:

```sh
docker restart <container>
```

### Platform Notes

- **Docker/Kubernetes/headless hosts**: pass JSON directly so no TTY is required, then restart the container or pod from its orchestrator.
- **Linux/BSD/OpenWrt**: the CLI can restart the known service manager, or prints the exact manual restart guidance.
- **macOS/Windows desktop**: configuration storage and the WireGuard device path are shared with the daemon; restart behavior follows the installed desktop/service variant.
- **Android/iOS**: AWG v2/v3 preferences and device application remain in the shared Go core. Mobile UI packaging is separate, so distribute the same profile through the app/control integration rather than relying on the desktop CLI.
- **Historical v2**: old JSON using `JC`/`H1` field names, lowercase names, scalar headers, or header ranges remains accepted. AmneziaWG 2.0 retired the legacy `<c>` CPS counter tag; remove `<c>` while retaining the other tags. Applying a v2 profile clears v3-only state.

## Configuration Parameters

| Parameter | Description | Default | Recommended | Compatibility |
|-----------|-------------|---------|-------------|---------------|
| `jc` | Junk packet count | 0 | 3-6 | ✅ Safe with standard WG |
| `jmin` | Min junk packet size (bytes) | 0 | 40-50 | ✅ Safe with standard WG |
| `jmax` | Max junk packet size (bytes) | 0 | 70-100 | ✅ Safe with standard WG |
| `s1` | Init packet prefix length (0-64) | 0 | 10-20 (advanced) | ❌ Breaks standard WG |
| `s2` | Response packet prefix length (0-64) | 0 | 10-20 (advanced) | ❌ Breaks standard WG |
| `s3` | Cookie packet prefix length (0-64) | 0 | Profile-specific | Must match AWG peers |
| `s4` | Transport packet prefix length (0-64) | 0 | Profile-specific | Must match AWG peers |
| `h1`-`h4` | Message header values or ranges | Standard WG types | Profile-specific | Must match AWG peers |
| `i1` | Primary signature packet (CPS format) | "" | Protocol-specific | ✅ Safe with standard WG |
| `i2` | Secondary signature packet (CPS format) | "" | Optional entropy | ✅ Safe with standard WG |
| `i3` | Tertiary signature packet (CPS format) | "" | Optional entropy | ✅ Safe with standard WG |
| `i4` | Quaternary signature packet (CPS format) | "" | Optional entropy | ✅ Safe with standard WG |
| `i5` | Quinary signature packet (CPS format) | "" | Optional entropy | ✅ Safe with standard WG |
| `header_protection_key` | AWG v3 32-byte key encoded as 64 hex characters | "" | Profile-specific | Requires AWG v3; must match peers |
| `content_padding_addition` | AWG v3 transport padding range | 0 | `5-31` | Requires v3-capable core |
| `rekey_after_time` | Rekey interval range in seconds | 0 | `120-180` | Local timing |
| `rekey_timeout` | Rekey timeout range in seconds | 0 | `5-7` | Local timing |
| `reject_after_time` | Session rejection range in seconds | 0 | `180-240` | Local timing |
| `keepalive_timeout` | Keepalive timeout range in seconds | 0 | `10-15` | Local timing |
| `max_handshake_attempts` | Handshake attempt-count range | 0 | `8-12` | Local timing |

### Custom Protocol Signature (CPS) Format

CPS packets use tag-based format to emulate protocols:

| Tag | Format | Description | Example |
|-----|---------|-------------|---------|
| `b` | `<b hex_data>` | Static bytes to emulate protocols | `<b 0xc0>` (QUIC header) |
| `t` | `<t>` | Unix timestamp (32-bit, network byte order) | `<t>` |
| `r` | `<r length>` | Cryptographically secure random bytes | `<r 16>` |
| `rc` | `<rc length>` | Random ASCII letters | `<rc 16>` |
| `rd` | `<rd length>` | Random decimal digits | `<rd 16>` |
| `d` | `<d>` | Original input bytes (empty for I1-I5 packets) | `<d>` |
| `ds` | `<ds>` | Base64 form of input (empty for I1-I5 packets) | `<ds>` |
| `dz` | `<dz length>` | Encoded input-size field of the selected length | `<dz 2>` |

Lengths must be non-negative and the generated I-packet must fit in one safe
UDP datagram. The retired `<c>` counter tag is distinct from hexadecimal byte
data: `<b 0xc0>` remains valid, while `<c>` does not.

**Examples:**

- Static header: `<b 0xc0000000>` (4-byte fixed header)
- With random data: `<b 0x1234><r 16>` (header + 16 random bytes)
- With timestamp/random data: `<b 0xabcd><t><r 8>` (header + timestamp + random data)

**⚠️ Important**: Don't use random examples! To create effective CPS signatures:

1. **Capture real traffic** with Wireshark or tcpdump from the protocol you want to mimic
2. **Extract hex patterns** from actual packet headers
3. **Build CPS format** using captured hex data with `<b hex_pattern>`
4. **Add dynamic fields** like `<t>`, `<r length>`, `<rc length>`, or `<rd length>` as needed

**💡 Pro tip**: CPS signatures (i1-i5) are advanced junk packets that can replace basic junk packets. More i1-i5 signatures = fewer jc packets needed for effective DPI evasion.

📖 **Complete guide**: [AmneziaWG Self-Hosted Setup](https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted)

## CLI Commands

```bash
# AmneziaWG v2/v3 commands
tailscale awg set '{"jc":4,"jmin":40,"jmax":70}'                     # Basic DPI evasion (prompt to restart)
tailscale awg set '{"jc":4,"i1":"<b 0xc0><r 32><t>"}'                # Protocol masking (prompt to restart)
tailscale awg set                                                     # Generator: v3 default, v2 selectable
tailscale awg get                                                     # Show current config
tailscale awg reset                                                   # Reset to standard WG (prompt to restart)
tailscale awg sync                                                    # Discover/sync from online peers

# General set command with Amnezia-WG flag
tailscale set --amnezia-wg='{"jc":4,"jmin":40,"jmax":70}'
```

## Environment Variables

Set these before starting tailscaled:

```bash
export TS_AMNEZIA_JC=4        # Junk packet count
export TS_AMNEZIA_JMIN=40     # Min junk packet size
export TS_AMNEZIA_JMAX=70     # Max junk packet size
export TS_AMNEZIA_S1=0        # Init packet prefix length
export TS_AMNEZIA_S2=0        # Response packet prefix length
export TS_AMNEZIA_S3=0        # Cookie packet prefix length
export TS_AMNEZIA_S4=0        # Transport packet prefix length
export TS_AMNEZIA_H1=0        # Init header (0 uses standard type 1)
export TS_AMNEZIA_H2=0        # Response header (0 uses standard type 2)
export TS_AMNEZIA_H3=0        # Cookie header (0 uses standard type 3)
export TS_AMNEZIA_H4=0        # Transport header (0 uses standard type 4)
export TS_AMNEZIA_I1='<b 0xc0><r 32><t>'        # Primary signature packet (CPS format)
export TS_AMNEZIA_I2=''       # Secondary signature packet (CPS format)
export TS_AMNEZIA_I3=''       # Tertiary signature packet (CPS format)
export TS_AMNEZIA_I4=''       # Quaternary signature packet (CPS format)
export TS_AMNEZIA_I5=''       # Quinary signature packet (CPS format)
export TS_AMNEZIA_HEADER_PROTECTION_KEY=''       # 64 hex chars; empty disables v3 header protection
export TS_AMNEZIA_CONTENT_PADDING_ADDITION='0'   # e.g. 5-31
export TS_AMNEZIA_REKEY_AFTER_TIME='0'           # e.g. 120-180
export TS_AMNEZIA_REKEY_TIMEOUT='0'              # e.g. 5-7
export TS_AMNEZIA_REJECT_AFTER_TIME='0'           # e.g. 180-240
export TS_AMNEZIA_KEEPALIVE_TIMEOUT='0'           # e.g. 10-15
export TS_AMNEZIA_MAX_HANDSHAKE_ATTEMPTS='0'      # e.g. 8-12
```

## Usage Scenarios

### 1. Conservative DPI Evasion (Most Common)

```bash
tailscale awg set '{"jc":4,"jmin":40,"jmax":70}'
```

- **Use case**: Most censorship environments
- **Impact**: Minimal bandwidth overhead, good compatibility
- **Effectiveness**: Bypasses basic DPI detection
- **Compatibility**: ✅ Works with standard Tailscale/WireGuard peers

### 2. Protocol Masking (Intermediate)

```bash
tailscale awg set '{"jc":4,"jmin":40,"jmax":70,"s1":10,"s2":15,"i1":"<b 0xc0><r 32><t>"}'
```

- **Use case**: Moderate DPI environments, needs to look like QUIC
- **Impact**: Moderate bandwidth overhead, advanced obfuscation
- **Effectiveness**: Strong DPI evasion with protocol mimicry
- **Compatibility**: ❌ Requires all communicating nodes to use this fork with matching `s1`/`s2`; `i1` may differ per sender

### 3. Full Signature Chain (Advanced)

```bash
tailscale awg set '{"jc":6,"s1":15,"s2":20,"i1":"<b 0xc0><r 32><t>","i2":"<b 0x40><r 16><t>","i3":"<r 20>","i4":"<rd 8><b 0x0001><r 8>","i5":"<t><r 12>"}'
```

- **Use case**: Strict DPI environments, maximum obfuscation
- **Impact**: Higher bandwidth overhead, complex signature chain
- **Effectiveness**: Maximum DPI evasion with multi-level obfuscation
- **Compatibility**: ❌ Requires all communicating nodes to use this fork; `s1`-`s4` must match, while `i1`-`i5` may differ per sender

### 4. Standard WireGuard (Default)

```bash
tailscale awg reset
```

- **Use case**: Normal networks, maximum performance
- **Impact**: No overhead, maximum compatibility
- **Effectiveness**: No DPI evasion
- **Compatibility**: ✅ Full compatibility with all WireGuard implementations

## Restart Requirements

| Configuration Method | Restart Required |
|---------------------|------------------|
| `tailscale awg set` | Prompted (Y/n) |
| `tailscale awg reset` | Prompted (Y/n) |
| `tailscale set --amnezia-wg` | Prompted (Y/n) |
| Environment variables | Yes (tailscaled) |

## Compatibility

| Peer Type | Junk Packets | Handshake Obfuscation | Protocol Masking |
|-----------|--------------|----------------------|------------------|
| This fork (AWG v2/v3) | ✅ Supported | ✅ Supported | ✅ Supported |
| This fork (1.0 mode) | ✅ Supported | ✅ Supported | ❌ N/A |
| Standard Tailscale | ✅ Ignored | ❌ May fail | ❌ May fail |
| Standard WireGuard | ✅ Ignored | ❌ May fail | ❌ May fail |

### ⚠️ Important Compatibility Notes

**Junk packets (`jc`, `jmin`, `jmax`) and CPS signatures (`i1`-`i5`)**:

- ✅ **Safe with any WireGuard**: Standard peers ignore extra packets
- ✅ **Mixed networks**: Can mix this fork with standard Tailscale/WireGuard
- ✅ **Gradual deployment**: Upgrade nodes one by one
- ✅ **Independent settings**: Each node can use different values (both are per-node junk traffic)
- 💡 **Optimization tip**: More CPS signatures = fewer basic junk packets needed

**Handshake and transport obfuscation (`s1`-`s4`, `h1`-`h4`, HeaderProtectionKey)**:

- ❌ **Breaks standard WireGuard**: Connection will fail
- ❌ **All-or-nothing**: ALL nodes in your network must use this fork
- ❌ **Same config required**: All nodes need identical `s1`-`s4`, `h1`-`h4`, and HeaderProtectionKey values
- ✅ **v2 remains supported**: A v3-capable binary can sync a v2 profile; v3-only state is cleared before reconnecting
- ⚠️ **Header protection rule**: `s1`-`s4` must each be at least 12 when HeaderProtectionKey is enabled
- ✅ **AmneziaWG 1.0 compatibility**: When I1 is empty, works with AmneziaWG 1.0

### Recommended Approach for Mixed Environments

**For maximum compatibility (works with standard Tailscale):**

```bash
# Only use junk packets and CPS signatures - safe with any peer
# Each node can use different values independently
tailscale awg set '{"jc":2,"jmin":40,"jmax":70,"i1":"<b 0xc0><r 16>","i2":"<b 0x40><r 12>"}'

# Example: Node A uses CPS signatures, Node B uses basic junk packets
# Node A: '{"jc":1,"i1":"<b 0xc0><r 16>","i2":"<b 0x40><r 20>"}'  # Less jc, more CPS
# Node B: '{"jc":5,"jmin":50,"jmax":80}'                         # More jc, no CPS
# Both work fine together!
```

**For private networks (all nodes use this fork):**

```bash
# AWG v2 obfuscation - s1/s2 must match across nodes
tailscale awg set '{"jc":4,"jmin":40,"jmax":70,"s1":10,"s2":15,"i1":"<b 0xc0><r 32><t>"}'
```

**For AmneziaWG 1.0 compatibility:**

```bash
# Leave I1 empty to use AmneziaWG 1.0 mode (compatible with existing 1.0 deployments)
tailscale awg set '{"jc":4,"jmin":40,"jmax":70,"s1":10,"s2":15}'
```

## Troubleshooting

**Config not saving?**

- Use JSON format: `tailscale awg set '{"jc":4}'`
- Check permissions: run with `sudo` if needed

**Connection issues?**

- Try conservative settings first: `{"jc":3,"jmin":40,"jmax":60}`
- Reset to standard: `tailscale awg reset`
- **Mixed networks**: Only use junk packets (`jc`, `jmin`, `jmax`) and CPS signatures (`i1`-`i5`) if connecting to standard Tailscale
- **Junk traffic optimization**: Each node can use different values - no coordination needed. More CPS signatures = fewer basic junk packets needed
- **Handshake obfuscation**: Ensure ALL nodes use this fork with identical `s1,s2` values (i1-i5 can vary per node)
- **AmneziaWG 1.0 compatibility**: Leave `i1` empty to use 1.0 mode
- **Invalid CPS format**: Check CPS syntax: `<b hex>`, `<t>`, `<r length>`, `<rc length>`, `<rd length>`. Remove the retired `<c>` tag from legacy profiles.
- **Reset appears ineffective**: Unset any `TS_AMNEZIA_*` overlay and restart tailscaled/container; stored zero values do not override non-zero environment values.
- Check logs: `sudo journalctl -u tailscaled -f`

**Performance issues?**

- Reduce junk packet count: `{"jc":2}`
- Avoid complex CPS signatures unless necessary
- Use simple signatures: `{"i1":"<b 0xc0><r 16>"}`
- Reduce signature chain length (use fewer i2-i5 packets)
- Monitor bandwidth overhead with signature packets

## Technical Details

- **Implementation**: Extends Tailscale's preference system
- **Storage**: Persisted in tailscaled state file
- **Scope**: Per-node configuration
- **Protocol**: Compatible with AWG v2 and AWG v3 wire formats
- **Security**: Maintains WireGuard's cryptographic guarantees
- **Input safety**: Shared validation protects CLI, LocalAPI, peer sync, environment overlays, and UAPI generation
- **Obfuscation**: Multi-level transport layer obfuscation (headers, handshake, protocol masking)
- **Performance**: Single-pass AEAD encryption with SIMD optimization
- **Backward compatibility**: Full compatibility when all parameters are zero/empty

## Migration and Profile Downgrade

1. Existing v2 JSON remains accepted, including scalar or range `h1`-`h4` values, except for the retired `<c>` CPS tag. Remove `<c>` and keep the remaining tags.
2. AWG v3 adds HeaderProtectionKey, content padding, and timing ranges without changing the v2 field names.
3. Syncing or setting a v2 profile on a node that previously used v3 clears all v3-only settings.
4. Standard WireGuard mode is restored by `tailscale awg reset`.

## License

BSD 3-Clause (same as Tailscale)

---

**Default behavior is identical to standard Tailscale.** AWG v2/v3 features are only active when explicitly configured.
