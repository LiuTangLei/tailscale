#!/bin/sh
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause
# Install this fork through its maintained Linux installer.
# TAILSCALE_VERSION=1.104.4 optionally pins a release; default: latest stable.
# Usage: curl -fsSL https://raw.githubusercontent.com/LiuTangLei/tailscale/main/scripts/installer.sh | sh
set -eu

main() {
    command -v bash >/dev/null 2>&1 || { echo "Please install bash first." >&2; return 1; }
    installer=$(mktemp)
    trap 'rm -f "$installer"' EXIT
    url="https://raw.githubusercontent.com/LiuTangLei/tailscale-awg-installer/main/install-linux.sh"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$installer"
    else
        wget -qO "$installer" "$url"
    fi
    case "${TAILSCALE_VERSION:-}" in
        "") ;;
        v*) set -- --version "$TAILSCALE_VERSION" "$@" ;;
        *) set -- --version "v$TAILSCALE_VERSION" "$@" ;;
    esac
    case "${TRACK:-stable}" in
        stable) ;;
        unstable) set -- --pre-release "$@" ;;
        *) echo "TRACK must be stable or unstable" >&2; return 1 ;;
    esac
    bash "$installer" "$@"
}
main "$@"
