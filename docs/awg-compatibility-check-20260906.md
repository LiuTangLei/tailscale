# AWG compatibility check (2026-09-06)

## Scope

This check focused on the currently pinned fork's historical AWG/Amnezia-WG compatibility surface:

- legacy scalar H1-H4 JSON acceptance
- snake_case v3 field compatibility
- v2 range and CPS validation (including rejection of retired `<c>`)
- v2 -> v3.1 -> v2 zeroing behavior for new flags
- zero/native configuration behavior
- older config capability/version negotiation

No production bug fix was required for the current branch after review; the code already enforces the compatibility rules described below.

## Evidence

Command run:

```bash
cd /Users/lei/.devspace/worktrees/tailscale-26395428 && go test ./ipn ./cmd/tailscale/cli ./wgengine/wgcfg ./disco
```

Result:

```text
ok   tailscale.com/ipn      0.206s
ok   tailscale.com/cmd/tailscale/cli    0.417s
ok   tailscale.com/wgengine/wgcfg       0.009s
ok   tailscale.com/disco      0.006s
```

## What the existing tests cover

- `ipn/prefs_test.go`
  - `TestAmneziaWGPrefsJSONV2AndV3`: accepts legacy scalar H1 values and current snake_case v3 fields.
  - `TestAmneziaWGPrefsVersions`: validates `IsZero`, `IsV3`, and version classification semantics.

- `ipn/amnezia_test.go`
  - `TestValidateAmneziaWGConfigHistoricalV2`: accepts historical AWG v2 values.
  - `TestValidateAmneziaWGConfigRejectsUnsafeValues`: rejects invalid CPS and overlapping ranges.
  - `TestValidateAmneziaWGConfigV3HeaderProtection`: verifies v3 padding/header key rules.
  - `TestMarshalAmneziaWGConfigForDiscoUsesValidationLimit`: checks serialization limits and validation behavior.

- `cmd/tailscale/cli/amnezia_test.go`
  - `TestAmneziaConfigVersionCompatibility`: checks v2/v3 version classification.
  - `TestValidateAmneziaWGConfigRejectsRetiredCounterTag`: ensures retired CPS tag `<c>` is rejected.

- `disco/disco_test.go`
  - `TestAmneziaWGConfigRequestVersionCompatibility`: confirms legacy discovery requests still negotiate v2 only, while newer requests accept v3.

## Compatibility statement

The current tree continues to accept historical AWG configuration data without silently fabricating a profile. Newer v3/v3.1 fields are explicitly recognized, but unsupported historical wire formats are rejected instead of being silently ignored. This keeps compatibility with older peers and configs while preserving the current safety checks for the newer format.

## Added transition regression

`wgengine/wgcfg/awg_legacy_roundtrip_test.go` now tests legacy scalar and
range-string H1-H4 JSON, CPS data, and three consecutive v2 -> v3.1 -> v2
roundtrips on the same actual WG device. The complete UAPI state must equal
the initial v2 state; random_trailers and disable_cookies must be zero. A final
native reset must remove header protection, content padding and CPS payloads.
The four compatibility packages were rerun with `-count=3`, all passed.

## Gaps / limitations

- The check is intentionally scoped to the repo and pinned fork in this worktree; it does not claim compatibility against any external older implementation outside the current branch.
- No QUIC transport or congestion changes were touched in this pass.
