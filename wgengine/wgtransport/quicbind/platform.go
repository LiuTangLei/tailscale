// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package quicbind

// Mobile VPN services can become available after engine creation. Their
// existing magicsock rebind hooks protect/rebind sockets when that happens.
// A second UDP socket would not participate in that host lifecycle yet, so
// fail closed rather than claim protection merely because initial build works.
// Native QUIC-IP and HTTP/3 remain available over the protected host Bind.
func supportsIndependentUDP(goos string) bool {
	return goos != "android" && goos != "ios" && goos != "js"
}
