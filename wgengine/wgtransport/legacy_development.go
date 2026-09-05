// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_dev_wg_over_quic

package wgtransport

// LegacyWGOverQUIC permits the old double-encryption carrier only in an
// explicitly selected development build. Never enable this tag in releases.
const LegacyWGOverQUIC = true
