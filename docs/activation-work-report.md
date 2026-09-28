# Activation work report

## Summary

This change fixes the AWG/QUIC activation bug where a selection could be written to the daemon config but left in a `pending_restart` state instead of being activated immediately.

The fix introduces one shared default path for mutation commands:

- apply the config change
- restart the local tailscaled service
- verify the active mode/desired mode matches and `pending_restart` clears
- fail explicitly if the config persists but the daemon does not become active

This applies to the AWG set/sync/reset flow and the transport/server selection paths.

## Default behavior

The CLI now restarts the daemon automatically by default for managed transport and AWG changes unless the user explicitly passes `--no-restart`.

This preserves the intended semantics for staging-only test and smoke workflows while ensuring actual user-initiated selections take effect immediately.

## Safety checks

- custom socket / non-default daemon restart is rejected instead of restarting the wrong service
- container/embedded hosts without a safe restart path fail clearly instead of claiming success
- the legacy restart prompt is not repeated after a confirmed mutation
- interactive confirmation still preserves scanner input and does not consume follow-up prompts

## Validation

Focused validation was run in the CLI package:

- `go test ./cmd/tailscale/cli -count=1`

This passed successfully. Parent review additionally ran the CLI race suite and real isolated two-node AWG/QUIC/sync smoke checks. Regression coverage now includes default --yes activation, idempotent QUIC selection, cancellation and EOF without mutation, custom-socket/container preflight, explicit --no-restart staging, restart failure, verification deadline, active-native checks for AWG, redacted mismatch errors, and ffcli flag parsing for sync/reset.

Verification uses a shared context deadline so a blocked LocalAPI request cannot bypass the timeout. Service-manager invocations are bounded and macOS sudo is noninteractive. Unsupported/custom-socket automatic restarts are rejected before configuration changes, rather than silently leaving a staged selection. The script's late sync-phase commands explicitly opt into --no-restart too.

## Limitations

- No host or remote restart was executed during validation.
- The change intentionally avoids privileged generic kill/exec endpoints and dynamic engine hot-swaps.
- Parent deployment or wrapper layers remain responsible for wider rollout and host-specific service orchestration.
