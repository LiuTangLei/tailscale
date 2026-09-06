// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build ts_http3_queue_overlay

package quicbind

import (
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const http3ReceiveQueueCapacity = http3.TunnelDatagramQueueCapacity
const quicReceiveQueueCapacity = quic.TunnelDatagramReceiveQueueCapacity
