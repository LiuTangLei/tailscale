// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_dev_wg_over_quic

package wgtransport

// LegacyWGOverQUIC is false in all normal distribution builds. Compatibility
// with existing peers uses Native, not a second encryption layer.
const LegacyWGOverQUIC = false
