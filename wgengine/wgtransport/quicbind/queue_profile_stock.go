// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !ts_http3_queue_overlay

package quicbind

// Stock quic-go v0.62.0. Distribution builds use the checked-in Go overlay.
const http3ReceiveQueueCapacity = 32
const quicReceiveQueueCapacity = 128
