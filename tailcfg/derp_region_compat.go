// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

// DERPRegionID names the region identifier used by newer consumers such as
// tailcat v0.6. It is an alias so the 1.102 data-plane APIs keep their existing
// representation and source compatibility.
type DERPRegionID = int
