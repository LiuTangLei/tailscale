// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/transportprofile"
	"tailscale.com/wgengine/wgtransport"
)

type h3BulkSample struct {
	Seconds       float64 `json:"seconds"`
	ReceivedBytes int64   `json:"received_bytes"`
	IntervalMbps  float64 `json:"interval_mbps"`
}

type h3BulkTransfer struct {
	Direction     string             `json:"direction"`
	OuterSession  string             `json:"outer_session"`
	Bytes         int64              `json:"bytes"`
	Seconds       float64            `json:"seconds"`
	Mbps          float64            `json:"mbps"`
	DialSeconds   float64            `json:"dial_seconds"`
	First64KiB    float64            `json:"first_64kib_seconds"`
	FirstMiB      float64            `json:"first_mib_seconds"`
	First10MiB    float64            `json:"first_10mib_seconds,omitempty"`
	SHA256        string             `json:"sha256"`
	VerifySeconds float64            `json:"verify_seconds"`
	Samples       []h3BulkSample     `json:"samples"`
	Before        [2]map[string]any  `json:"before"`
	After         [2]map[string]any  `json:"after"`
	RoutesBefore  [2]h3BulkRoute     `json:"routes_before"`
	RoutesAfter   [2]h3BulkRoute     `json:"routes_after"`
	LinksBefore   [2]h3BulkLinkStats `json:"links_before"`
	LinksAfter    [2]h3BulkLinkStats `json:"links_after"`
}

type h3BulkRoute struct {
	CurrentAddress string `json:"current_address"`
	DERPRegion     string `json:"derp_region"`
	PeerRelay      string `json:"peer_relay"`
	Active         bool   `json:"active"`
}

func h3BulkNodeRoute(t *testing.T, ctx context.Context, node *Server) h3BulkRoute {
	t.Helper()
	client, err := node.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(ctx)
	if err != nil || len(status.Peer) != 1 {
		t.Fatalf("bulk route status unavailable: %v", err)
	}
	for _, peer := range status.Peer {
		return h3BulkRoute{CurrentAddress: peer.CurAddr, DERPRegion: peer.Relay, PeerRelay: peer.PeerRelay, Active: peer.Active}
	}
	panic("no bulk peer")
}

// TestManagedH3BulkFile is deliberately opt-in: it writes a 200 MiB temporary
// file and sends the whole file in each direction through real inner TCP,
// CONNECT-IP and QUIC DATAGRAM. The default suite never runs this benchmark.
//
// TS_H3_BULK=1 enables it. TS_H3_BULK_BYTES permits a small smoke run;
// TS_H3_BULK_RESULT and TS_H3_BULK_LABEL select a JSON artifact and variant label.
// TS_H3_BULK_SHAPE=1 adds a test-only 20 Mbps / 60 ms RTT / 600000-byte FIFO.
// TS_H3_BULK_MBPS overrides the shaped rate (1..1000); FIFO scales to four BDP.
// TS_H3_BULK_BYTES supports 1 MiB..8 GiB with streaming file creation/checksums.
// TS_H3_BULK_WARM_PROFILE=1 discovers the server declaration, resets the outer
// connection, and requires chromium-h3 on the measured reconnect.
// This local userspace result is not a WAN or kernel-TCP benchmark.
func TestManagedH3BulkFile(t *testing.T) {
	if os.Getenv("TS_H3_BULK") != "1" {
		t.Skip("opt-in 200 MiB H3/inner-TCP file benchmark; set TS_H3_BULK=1")
	}
	// Keep this localhost benchmark from creating router port mappings. The
	// knob is process-local and restored after both temporary nodes close.
	previousPortMapper := os.Getenv("TS_DISABLE_PORTMAPPER")
	t.Setenv("TS_DISABLE_PORTMAPPER", "true")
	envknob.Setenv("TS_DISABLE_PORTMAPPER", "true")
	t.Cleanup(func() { envknob.Setenv("TS_DISABLE_PORTMAPPER", previousPortMapper) })
	shape := os.Getenv("TS_H3_BULK_SHAPE") == "1"
	warmProfile := os.Getenv("TS_H3_BULK_WARM_PROFILE") == "1"
	mbps := int64(20)
	if value := os.Getenv("TS_H3_BULK_MBPS"); value != "" {
		var err error
		mbps, err = strconv.ParseInt(value, 10, 64)
		if err != nil || mbps < 1 || mbps > 1000 {
			t.Fatal("TS_H3_BULK_MBPS must be between 1 and 1000")
		}
	}
	bytesPerSecond := mbps * 1_000_000 / 8
	queueBytes := int(bytesPerSecond * int64(8*h3BulkLinkDelay) / int64(time.Second))
	expectedProfile := "none"
	if warmProfile {
		expectedProfile = "chromium-h3"
	}
	size := int64(200 << 20)
	if value := os.Getenv("TS_H3_BULK_BYTES"); value != "" {
		var err error
		size, err = strconv.ParseInt(value, 10, 64)
		if err != nil || size < 1<<20 || size > 8<<30 {
			t.Fatal("TS_H3_BULK_BYTES must be between 1 MiB and 8 GiB")
		}
	}
	document := struct {
		Passed             bool             `json:"passed"`
		Label              string           `json:"label"`
		Scope              string           `json:"scope"`
		GOOS               string           `json:"goos"`
		GOARCH             string           `json:"goarch"`
		GoVersion          string           `json:"go_version"`
		FileBytes          int64            `json:"file_bytes"`
		SourceSHA256       string           `json:"source_sha256"`
		SampleIntervalMS   int              `json:"sample_interval_ms"`
		Transfers          []h3BulkTransfer `json:"transfers"`
		ClientHelloProfile string           `json:"expected_client_hello_profile"`
		Shaping            map[string]any   `json:"shaping,omitempty"`
	}{Label: os.Getenv("TS_H3_BULK_LABEL"), Scope: "local unshaped tsnet userspace TCP -> automatic H3 CONNECT-IP -> QUIC DATAGRAM; temporary testcontrol/DERP and node state, no production daemon or OS TUN", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version(), FileBytes: size, SampleIntervalMS: 250}
	document.ClientHelloProfile = expectedProfile
	if shape {
		document.Scope = "local tsnet userspace TCP -> automatic H3 CONNECT-IP -> QUIC DATAGRAM -> test-only shaped Host.Bind.Send -> unchanged magicsock; no production daemon or OS networking changes"
		document.Shaping = map[string]any{"mbps_each_direction": mbps, "one_way_delay_ms": 30, "fifo_bytes_each_direction": queueBytes, "accounting": "outer QUIC payload bytes; UDP/IP overhead excluded; FIFO includes propagation-delayed packets"}
	}
	defer func() {
		document.Passed = !t.Failed() && len(document.Transfers) == 2
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Error(err)
			return
		}
		if output := os.Getenv("TS_H3_BULK_RESULT"); output != "" {
			if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(output, append(encoded, '\n'), 0600); err != nil {
				t.Error(err)
			}
		}
	}()
	transferTimeout := max(5*time.Minute, time.Duration(float64(size)/float64(bytesPerSecond)*float64(4*time.Second))+time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 2*transferTimeout+2*time.Minute)
	defer cancel()
	controlURL, control := startControl(t)
	control.AllNodesSameUser = true
	control.AllOnline = true
	roots := [2]string{t.TempDir(), t.TempDir()}
	var nodes [2]*Server
	var clients [2]*local.Client
	var ips [2]netip.Addr
	var transportConfigs [2]wgtransport.Config
	var factories [2]*h3BulkFactory
	defer func() {
		for _, s := range nodes {
			if s != nil {
				_ = s.Close()
			}
		}
	}()
	start := func(i int) {
		t.Helper()
		nodes[i] = &Server{Dir: roots[i], Hostname: fmt.Sprintf("h3-bulk-%d", i), ControlURL: controlURL, Logf: t.Logf, UserLogf: t.Logf, Transport: transportConfigs[i]}
		status, err := nodes[i].Up(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ips[i] = status.TailscaleIPs[0]
		clients[i], err = nodes[i].LocalClient()
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range nodes {
		start(i)
		before, err := clients[i].TransportStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		staged, err := clients[i].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "mode", Mode: "http3-ip", ExpectedRevision: before.Revision})
		if err != nil || !staged.AutoTrust || len(staged.Peers) != 0 {
			t.Fatalf("stage no-card H3: %v", err)
		}
		if i == 1 {
			yes := true
			if _, err := clients[i].ConfigureTransport(ctx, ipn.TransportControlRequest{Action: "server", Server: &yes, ExpectedRevision: staged.Revision}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := range nodes {
		_ = nodes[i].Close()
		nodes[i] = nil
	}
	if shape || warmProfile {
		for i := range nodes {
			config, _, err := transportprofile.LoadForStart(roots[i])
			if err != nil {
				t.Fatal(err)
			}
			factories[i] = &h3BulkFactory{Factory: config.Factory, shape: shape, bytesPerSecond: bytesPerSecond, queueBytes: queueBytes}
			config.Factory = factories[i]
			transportConfigs[i] = config
		}
	}
	for i := range nodes {
		start(i)
	}
	for i := range nodes {
		deadline := time.Now().Add(10 * time.Second)
		for {
			status, err := clients[i].Status(ctx)
			if err == nil && len(status.Peer) == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("bulk peer not distributed by local control")
			}
			time.Sleep(20 * time.Millisecond)
		}
		status, err := clients[i].TransportStatus(ctx)
		if err != nil || status.ActiveMode != "http3-ip" || (factories[i] == nil && status.Authentication != "node-key") {
			t.Fatalf("bulk node did not activate automatic H3: %+v, %v", status, err)
		}
		diagnostics, err := nodes[i].PacketTransportDiagnostics()
		if err != nil || diagnostics["authentication"] != "node-key" {
			t.Fatalf("bulk backend did not activate node-key authentication: %+v, %v", diagnostics, err)
		}
	}
	files := t.TempDir()
	source := filepath.Join(files, "source.bin")
	f, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.CopyN(io.MultiWriter(f, hash), rand.New(rand.NewSource(20260907)), size)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("create source file: %v, %v", err, closeErr)
	}
	document.SourceSHA256 = hex.EncodeToString(hash.Sum(nil))
	t.Logf("H3_BULK_SOURCE bytes=%d shape_Mbps=%d SHA256=%s", size, mbps, document.SourceSHA256)
	if warmProfile {
		probeCtx, probeCancel := context.WithTimeout(ctx, 20*time.Second)
		pong, err := clients[0].Ping(probeCtx, ips[1], tailcfg.PingTSMP)
		probeCancel()
		if err != nil || pong == nil || pong.Err != "" {
			t.Fatalf("discover authenticated H3 server: %+v, %v", pong, err)
		}
		for _, factory := range factories {
			if err := factory.reconnect(); err != nil {
				t.Fatal(err)
			}
		}
	}
	for from := range nodes {
		transfer := h3BulkFileTransfer(t, ctx, nodes, ips, factories, from, source, filepath.Join(files, "received.bin"), size, expectedProfile, transferTimeout)
		if warmProfile && from == 0 {
			transfer.OuterSession = "fresh QUIC after authenticated server discovery"
		}
		if transfer.SHA256 != document.SourceSHA256 {
			t.Fatal("received file SHA-256 differs from source file")
		}
		document.Transfers = append(document.Transfers, transfer)
		t.Logf("H3_BULK %s %s bytes=%d seconds=%.3f Mbps=%.3f firstMiB=%.3f SHA256=%s", document.Label, transfer.Direction, transfer.Bytes, transfer.Seconds, transfer.Mbps, transfer.FirstMiB, transfer.SHA256)
	}
}

func h3BulkFileTransfer(t *testing.T, ctx context.Context, nodes [2]*Server, ips [2]netip.Addr, factories [2]*h3BulkFactory, from int, source, destination string, size int64, expectedProfile string, transferTimeout time.Duration) h3BulkTransfer {
	t.Helper()
	result := h3BulkTransfer{Direction: []string{"ordinary -> declared server", "declared server -> ordinary"}[from], OuterSession: []string{"cold first transfer", "warm reverse transfer"}[from]}
	for i, node := range nodes {
		var err error
		result.Before[i], err = node.PacketTransportDiagnostics()
		if err != nil {
			t.Fatal(err)
		}
		result.RoutesBefore[i] = h3BulkNodeRoute(t, ctx, node)
		if factory := factories[i]; factory != nil && factory.link != nil {
			result.LinksBefore[i] = factory.link.snapshot()
		}
	}
	ln, err := nodes[from^1].Listen("tcp", ":18089")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	start := time.Now()
	var progress atomic.Int64
	stopSamples := make(chan struct{})
	samplesDone := make(chan []h3BulkSample, 1)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		samples := []h3BulkSample{{}}
		lastTime, lastBytes := start, int64(0)
		lastLog := start
		sample := func() {
			now, received := time.Now(), progress.Load()
			samples = append(samples, h3BulkSample{Seconds: now.Sub(start).Seconds(), ReceivedBytes: received, IntervalMbps: float64(received-lastBytes) * 8 / now.Sub(lastTime).Seconds() / 1e6})
			if now.Sub(lastLog) >= 10*time.Second {
				t.Logf("H3_BULK_PROGRESS from=%d seconds=%.1f GiB=%.3f cumulative_Mbps=%.2f", from, now.Sub(start).Seconds(), float64(received)/(1<<30), float64(received)*8/now.Sub(start).Seconds()/1e6)
				lastLog = now
			}
			lastTime, lastBytes = now, received
		}
		for {
			select {
			case <-ticker.C:
				sample()
			case <-stopSamples:
				sample()
				samplesDone <- samples
				return
			}
		}
	}()
	defer close(stopSamples)
	type received struct {
		result h3BulkTransfer
		err    error
	}
	receiverDone := make(chan received, 1)
	go func() {
		got := h3BulkTransfer{}
		var receiveErr error
		defer func() { receiverDone <- received{got, receiveErr} }()
		c, err := ln.Accept()
		if err != nil {
			receiveErr = err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(transferTimeout))
		f, err := os.Create(destination)
		if err != nil {
			receiveErr = err
			return
		}
		defer f.Close()
		buffer := make([]byte, 64<<10)
		for got.Bytes < size {
			n, err := c.Read(buffer[:min(int64(len(buffer)), size-got.Bytes)])
			if n > 0 {
				if _, err := f.Write(buffer[:n]); err != nil {
					receiveErr = err
					return
				}
				got.Bytes += int64(n)
				progress.Store(got.Bytes)
				elapsed := time.Since(start).Seconds()
				if got.First64KiB == 0 && got.Bytes >= 64<<10 {
					got.First64KiB = elapsed
				}
				if got.FirstMiB == 0 && got.Bytes >= 1<<20 {
					got.FirstMiB = elapsed
				}
				if got.First10MiB == 0 && got.Bytes >= 10<<20 {
					got.First10MiB = elapsed
				}
			}
			if err != nil && got.Bytes < size {
				receiveErr = err
				return
			}
		}
		got.Seconds = time.Since(start).Seconds()
		got.Mbps = float64(got.Bytes) * 8 / got.Seconds / 1e6
		if err := f.Close(); err != nil {
			receiveErr = err
			return
		}
		verifyStart := time.Now()
		check, err := os.Open(destination)
		if err != nil {
			receiveErr = err
			return
		}
		hash := sha256.New()
		_, err = io.Copy(hash, check)
		_ = check.Close()
		if err != nil {
			receiveErr = err
			return
		}
		got.VerifySeconds = time.Since(verifyStart).Seconds()
		digest := hash.Sum(nil)
		got.SHA256 = hex.EncodeToString(digest)
		_, receiveErr = c.Write(digest)
	}()
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	c, err := nodes[from].Dial(dialCtx, "tcp", net.JoinHostPort(ips[from^1].String(), "18089"))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	result.DialSeconds = time.Since(start).Seconds()
	_ = c.SetDeadline(time.Now().Add(transferTimeout))
	f, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := io.CopyN(c, f, size)
	_ = f.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	var acknowledged [sha256.Size]byte
	if _, err := io.ReadFull(c, acknowledged[:]); err != nil {
		t.Fatal(err)
	}
	got := <-receiverDone
	if got.err != nil {
		t.Fatal(got.err)
	}
	if hex.EncodeToString(acknowledged[:]) != got.result.SHA256 {
		t.Fatal("receiver digest acknowledgment mismatch")
	}
	// Preserve metrics captured before dialing while taking receiver metrics.
	got.result.Direction, got.result.OuterSession = result.Direction, result.OuterSession
	got.result.DialSeconds, got.result.Before = result.DialSeconds, result.Before
	got.result.RoutesBefore = result.RoutesBefore
	got.result.LinksBefore = result.LinksBefore
	result = got.result
	stopSamples <- struct{}{}
	result.Samples = <-samplesDone
	for i, node := range nodes {
		result.After[i], err = node.PacketTransportDiagnostics()
		if err != nil {
			t.Fatal(err)
		}
		result.RoutesAfter[i] = h3BulkNodeRoute(t, ctx, node)
		if factory := factories[i]; factory != nil && factory.link != nil {
			result.LinksAfter[i] = factory.link.snapshot()
			if result.LinksAfter[i].DeliveredBytes <= result.LinksBefore[i].DeliveredBytes || result.LinksAfter[i].MaxQueuedBytes > int64(factory.link.capacity()) {
				t.Fatalf("node %d bypassed the shaped path or exceeded its FIFO", i)
			}
		}
		stats := result.After[i]
		if stats["mode"] != "http3-ip" || stats["authentication"] != "node-key" || stats["http3"] != true || stats["datagrams"] != true || stats["wireguard_encryption"] != false {
			t.Fatalf("file transfer did not use authenticated H3 native-IP DATAGRAM: %+v", stats)
		}
		wantProfile := expectedProfile
		if i == 1 {
			// This diagnostic describes the local TLS stack. The receiving
			// server keeps standard TLS while node 0 emits chromium-h3.
			wantProfile = "none"
		}
		if stats["browser_fingerprint"] != wantProfile {
			t.Fatalf("node %d local ClientHello profile = %v, want %s", i, stats["browser_fingerprint"], wantProfile)
		}
		for _, counter := range []string{"http3_datagrams", "sent_packets", "received_packets"} {
			before, _ := result.Before[i][counter].(uint64)
			after, _ := stats[counter].(uint64)
			if after <= before {
				t.Fatalf("node %d counter %s did not advance", i, counter)
			}
		}
	}
	if factories[from] != nil && factories[from].link != nil {
		lowerBound := float64(size) / float64(factories[from].link.rate())
		if result.Seconds < lowerBound {
			t.Fatalf("file transfer escaped configured bottleneck: %.3fs < %.3fs", result.Seconds, lowerBound)
		}
	}
	return result
}
