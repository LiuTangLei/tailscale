# Tailscale with Amnezia-WG Integration

A Tailscale fork that integrates Amnezia-WG capabilities for DPI evasion and censorship circumvention while maintaining full backward compatibility with standard WireGuard.

## Key Features

- **Zero-config compatibility**: Behaves exactly like standard Tailscale by default
- **Runtime configuration**: Change settings without restarting tailscaled
- **Multiple interfaces**: CLI commands, JSON flags, and environment variables
- **DPI evasion**: Junk packet injection and header obfuscation
- **Backward compatible**: All zero values = standard WireGuard behavior

## Quick Start

### Basic DPI Evasion (Recommended)

```bash
# Add junk packets for basic DPI evasion (prompt to restart)
tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70}'

# Verify configuration
tailscale amnezia-wg get

# Reset to standard WireGuard (prompt to restart)
tailscale amnezia-wg reset
```

### Alternative Configuration Methods

```bash
# Via set command with JSON flag
tailscale set --amnezia-wg='{"jc":4,"jmin":40,"jmax":70}'

# Interactive configuration
tailscale amnezia-wg set
# (prompts for each parameter)

# Environment variables (requires tailscaled restart)
export TS_AMNEZIA_JC=4 TS_AMNEZIA_JMIN=40 TS_AMNEZIA_JMAX=70
sudo systemctl restart tailscaled
```

## Configuration Parameters

| Parameter | Description | Default | Recommended | Compatibility |
|-----------|-------------|---------|-------------|---------------|
| `jc` | Junk packet count | 0 | 3-6 | ✅ Safe with standard WG |
| `jmin` | Min junk packet size (bytes) | 0 | 40-50 | ✅ Safe with standard WG |
| `jmax` | Max junk packet size (bytes) | 0 | 70-100 | ✅ Safe with standard WG |
| `s1` | Init packet prefix length | 0 | 0 (advanced) | ❌ Breaks standard WG |
| `s2` | Response packet prefix length | 0 | 0 (advanced) | ❌ Breaks standard WG |
| `h1` | Init packet magic header | 1 | 1 (standard) | ❌ Breaks standard WG |
| `h2` | Response packet magic header | 2 | 2 (standard) | ❌ Breaks standard WG |
| `h3` | Underload packet magic header | 3 | 3 (standard) | ❌ Breaks standard WG |
| `h4` | Transport packet magic header | 4 | 4 (standard) | ❌ Breaks standard WG |

## CLI Commands

```bash
# Amnezia-WG specific commands
tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70}'  # Set config from JSON (prompt to restart)
tailscale amnezia-wg set                                 # Interactive setup (prompt to restart)
tailscale amnezia-wg get                                 # Show current config
tailscale amnezia-wg reset                               # Reset to standard WG (prompt to restart)

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
export TS_AMNEZIA_H1=1        # Init packet magic header
export TS_AMNEZIA_H2=2        # Response packet magic header
export TS_AMNEZIA_H3=3        # Underload packet magic header
export TS_AMNEZIA_H4=4        # Transport packet magic header
```

## Usage Scenarios

### 1. Conservative DPI Evasion (Most Common)

```bash
tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70}'
```

- **Use case**: Most censorship environments
- **Impact**: Minimal bandwidth overhead, good compatibility
- **Effectiveness**: Bypasses basic DPI detection
- **Compatibility**: ✅ Works with standard Tailscale/WireGuard peers

### 2. Aggressive Evasion

```bash
tailscale amnezia-wg set '{"jc":8,"jmin":50,"jmax":150,"s1":10,"s2":15}'
```

- **Use case**: Strict DPI environments
- **Impact**: Higher bandwidth overhead, may affect compatibility
- **Effectiveness**: Strong obfuscation
- **Compatibility**: ❌ Requires ALL nodes to use this fork with same config

### 3. Standard WireGuard (Default)

```bash
tailscale amnezia-wg reset
```

- **Use case**: Normal networks, maximum performance
- **Impact**: No overhead, maximum compatibility
- **Effectiveness**: No DPI evasion

## Restart Requirements

| Configuration Method | Restart Required |
|---------------------|------------------|
| `tailscale amnezia-wg set` | Prompted (Y/n) |
| `tailscale amnezia-wg reset` | Prompted (Y/n) |
| `tailscale set --amnezia-wg` | No |
| Environment variables | Yes (tailscaled) |

## Compatibility

| Peer Type | Junk Packets | Header Obfuscation | Handshake Obfuscation |
|-----------|--------------|-------------------|----------------------|
| This fork | ✅ Supported | ✅ Supported | ✅ Supported |
| Standard Tailscale | ✅ Ignored | ❌ May fail | ❌ May fail |
| Standard WireGuard | ✅ Ignored | ❌ May fail | ❌ May fail |

### ⚠️ Important Compatibility Notes

**Junk packets only (`jc`, `jmin`, `jmax`)**:

- ✅ **Safe with any WireGuard**: Standard peers ignore extra packets
- ✅ **Mixed networks**: Can mix this fork with standard Tailscale/WireGuard
- ✅ **Gradual deployment**: Upgrade nodes one by one
- ✅ **Independent settings**: Each node can use different junk packet values

**Header obfuscation (`s1`, `s2`, `h1-h4`)**:

- ❌ **Breaks standard WireGuard**: Connection will fail
- ❌ **All-or-nothing**: ALL nodes in your network must use this fork
- ❌ **Same config required**: All nodes need identical `s1,s2,h1-h4` values

### Recommended Approach for Mixed Environments

**For maximum compatibility (works with standard Tailscale):**

```bash
# Only use junk packets - safe with any peer
# Each node can use different values independently
tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70}'

# Example: Node A uses different values than Node B
# Node A: '{"jc":3,"jmin":30,"jmax":60}'
# Node B: '{"jc":5,"jmin":50,"jmax":80}'
# Both work fine together!
```

**For private networks (all nodes use this fork):**

```bash
# Full obfuscation - requires all nodes to use this fork
tailscale amnezia-wg set '{"jc":4,"jmin":40,"jmax":70,"s1":10,"s2":15,"h1":1234,"h2":5678}'
```

## Troubleshooting

**Config not saving?**

- Use JSON format: `tailscale amnezia-wg set '{"jc":4}'`
- Check permissions: run with `sudo` if needed

**Connection issues?**

- Try conservative settings first: `{"jc":3,"jmin":40,"jmax":60}`
- Reset to standard: `tailscale amnezia-wg reset`
- **Mixed networks**: Only use junk packets (`jc`, `jmin`, `jmax`) if connecting to standard Tailscale
- **Junk packets**: Each node can use different values - no coordination needed
- **Header obfuscation**: Ensure ALL nodes use this fork with identical `s1,s2,h1-h4` values
- Check logs: `sudo journalctl -u tailscaled -f`

**Performance issues?**

- Reduce junk packet count: `{"jc":2}`
- Avoid `s1`/`s2` parameters unless necessary
- Use standard header values (1,2,3,4)

## Technical Details

- **Implementation**: Extends Tailscale's preference system
- **Storage**: Persisted in tailscaled state file
- **Scope**: Per-node configuration
- **Protocol**: Compatible with Amnezia-WG wire format
- **Security**: Maintains WireGuard's cryptographic guarantees

## License

BSD 3-Clause (same as Tailscale)

---

**Default behavior is identical to standard Tailscale.** Amnezia-WG features are only active when explicitly configured.
