package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
)

const (
	minBenchBytes    = 1
	maxBenchBytes    = 256 << 20
	benchChunkSize   = 64 << 10
	maxBenchParallel = 4
	maxBenchRounds   = 3
)

type benchParams struct {
	Target    string
	Bytes     int
	Parallel  int
	Direction string
	Rounds    int
	Warmup    int
}

type benchStreamResult struct {
	Round      int     `json:"round"`
	Stream     int     `json:"stream"`
	Bytes      int     `json:"bytes"`
	DurationMS int64   `json:"duration_ms"`
	Mbps       float64 `json:"mbps"`
	SHA256     string  `json:"sha256,omitempty"`
	Error      string  `json:"error,omitempty"`
}

type benchMetrics struct {
	CPUUserSeconds  float64 `json:"cpu_user_seconds"`
	CPUSysSeconds   float64 `json:"cpu_sys_seconds"`
	CPUTotalSeconds float64 `json:"cpu_total_seconds"`
	RSSBytes        int64   `json:"rss_bytes,omitempty"`
	Goroutines      int     `json:"goroutines"`
	MemAllocBytes   int64   `json:"mem_alloc_bytes"`
	TotalAllocBytes uint64  `json:"total_alloc_bytes"`
	Mallocs         uint64  `json:"mallocs"`
	HeapAllocBytes  int64   `json:"heap_alloc_bytes"`
	HeapInuseBytes  int64   `json:"heap_inuse_bytes"`
	GCCount         uint32  `json:"gc_count"`
	GCPauseTotalMS  float64 `json:"gc_pause_total_ms"`
}

type benchResult struct {
	Target     string              `json:"target"`
	Direction  string              `json:"direction"`
	Bytes      int                 `json:"bytes"`
	Parallel   int                 `json:"parallel"`
	Rounds     int                 `json:"rounds"`
	Warmup     int                 `json:"warmup,omitempty"`
	DurationMS int64               `json:"duration_ms"`
	Mbps       float64             `json:"mbps"`
	Streams    []benchStreamResult `json:"streams"`
	Metrics    benchMetrics        `json:"metrics"`
}

func registerTailnetHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/bench-download", benchDownloadHandler)
	mux.HandleFunc("/bench-upload", benchUploadHandler)
}

func registerAdminHandlers(mux *http.ServeMux, n *node) {
	mux.HandleFunc("/metrics", n.metrics)
	mux.HandleFunc("/bench", n.bench)
	mux.HandleFunc("/latency", n.latency)
}

func (n *node) metrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, metricsSnapshot())
}

func metricsSnapshot() benchMetrics {
	out := benchMetrics{Goroutines: runtime.NumGoroutine()}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	out.MemAllocBytes = int64(ms.Alloc)
	out.TotalAllocBytes = ms.TotalAlloc
	out.Mallocs = ms.Mallocs
	out.HeapAllocBytes = int64(ms.HeapAlloc)
	out.HeapInuseBytes = int64(ms.HeapInuse)
	out.GCCount = ms.NumGC
	out.GCPauseTotalMS = float64(ms.PauseTotalNs) / float64(time.Millisecond)
	if runtime.GOOS == "linux" {
		if rss, err := linuxRSSBytes(); err == nil {
			out.RSSBytes = rss
		}
		out.CPUUserSeconds, out.CPUSysSeconds = processCPU()
		out.CPUTotalSeconds = out.CPUUserSeconds + out.CPUSysSeconds
	}
	return out
}

func linuxRSSBytes() (int64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return 0, fmt.Errorf("malformed VmRSS line: %q", line)
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return v * 1024, nil
	}
	return 0, errors.New("VmRSS not found")
}

func benchDownloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	bytes, err := parseBenchSize(r.URL.Query().Get("bytes"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(bytes))
	buf := make([]byte, benchChunkSize)
	for offset := 0; offset < bytes; {
		chunk := min(len(buf), bytes-offset)
		fillPattern(buf[:chunk], offset)
		if _, err := w.Write(buf[:chunk]); err != nil {
			return
		}
		offset += chunk
	}
}

func benchUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBenchBytes+1)
	var total int
	var offset int
	sha := sha256.New()
	buf := make([]byte, benchChunkSize)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			if total+n > maxBenchBytes {
				http.Error(w, fmt.Sprintf("body exceeds %d bytes", maxBenchBytes), http.StatusRequestEntityTooLarge)
				return
			}
			if err := verifyPattern(buf[:n], offset); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if _, writeErr := sha.Write(buf[:n]); writeErr != nil {
				http.Error(w, writeErr.Error(), http.StatusInternalServerError)
				return
			}
			total += n
			offset += n
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, fmt.Sprintf("read body: %v", err), http.StatusBadRequest)
			return
		}
	}
	if total == 0 {
		http.Error(w, "empty payload", http.StatusBadRequest)
		return
	}
	writeJSON(w, payloadResult{Bytes: total, SHA256: hex.EncodeToString(sha.Sum(nil))})
}

func (n *node) bench(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	params, err := parseBenchRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if params.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}
	if !n.opMu.TryLock() {
		http.Error(w, "operation in progress", http.StatusConflict)
		return
	}
	defer n.opMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	ip, err := netip.ParseAddr(params.Target)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid target %q: %v", params.Target, err), http.StatusBadRequest)
		return
	}
	st, err := n.lc.Status(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if !ipInPeerStatus(st, ip) {
		http.Error(w, fmt.Sprintf("target %s is not a known peer", ip), http.StatusBadRequest)
		return
	}
	if params.Warmup > 0 {
		if err := n.runBenchWarmup(ctx, ip, params); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	result, err := n.runBench(ctx, ip, params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, result)
}

func (n *node) runBenchWarmup(ctx context.Context, ip netip.Addr, params benchParams) error {
	for i := 0; i < params.Warmup; i++ {
		if _, err := n.runBenchStream(ctx, ip, params.Direction, params.Bytes, 0, 0); err != nil {
			return err
		}
	}
	return nil
}

func (n *node) runBench(ctx context.Context, ip netip.Addr, params benchParams) (benchResult, error) {
	start := time.Now()
	startMetrics := metricsSnapshot()
	streams := make([]benchStreamResult, 0, params.Parallel*params.Rounds)
	for round := 1; round <= params.Rounds; round++ {
		results := make(chan benchStreamResult, params.Parallel)
		for stream := 1; stream <= params.Parallel; stream++ {
			go func(stream int) {
				res, err := n.runBenchStream(ctx, ip, params.Direction, params.Bytes, round, stream)
				if err != nil {
					results <- benchStreamResult{Round: round, Stream: stream, Bytes: params.Bytes, Error: err.Error()}
					return
				}
				results <- res
			}(stream)
		}
		for stream := 0; stream < params.Parallel; stream++ {
			streams = append(streams, <-results)
		}
	}
	metricsAfter := metricsSnapshot()
	var totalBytes int
	for _, res := range streams {
		if res.Error == "" {
			totalBytes += res.Bytes
		}
	}
	elapsed := time.Since(start)
	result := benchResult{
		Target:     ip.String(),
		Direction:  params.Direction,
		Bytes:      params.Bytes,
		Parallel:   params.Parallel,
		Rounds:     params.Rounds,
		Warmup:     params.Warmup,
		DurationMS: elapsed.Milliseconds(),
		Streams:    streams,
		Metrics: benchMetrics{
			CPUUserSeconds:  metricsAfter.CPUUserSeconds - startMetrics.CPUUserSeconds,
			CPUSysSeconds:   metricsAfter.CPUSysSeconds - startMetrics.CPUSysSeconds,
			CPUTotalSeconds: metricsAfter.CPUTotalSeconds - startMetrics.CPUTotalSeconds,
			RSSBytes:        metricsAfter.RSSBytes,
			Goroutines:      metricsAfter.Goroutines,
			MemAllocBytes:   metricsAfter.MemAllocBytes - startMetrics.MemAllocBytes,
			TotalAllocBytes: metricsAfter.TotalAllocBytes - startMetrics.TotalAllocBytes,
			Mallocs:         metricsAfter.Mallocs - startMetrics.Mallocs,
			HeapAllocBytes:  metricsAfter.HeapAllocBytes - startMetrics.HeapAllocBytes,
			HeapInuseBytes:  metricsAfter.HeapInuseBytes - startMetrics.HeapInuseBytes,
			GCCount:         metricsAfter.GCCount - startMetrics.GCCount,
			GCPauseTotalMS:  metricsAfter.GCPauseTotalMS - startMetrics.GCPauseTotalMS,
		},
	}
	if elapsed > 0 {
		// Aggregate throughput uses WALL time, not the sum of concurrent stream
		// durations (which would incorrectly divide by the parallelism).
		result.Mbps = float64(totalBytes) * 8 / elapsed.Seconds() / 1e6
	}
	return result, nil
}

func (n *node) runBenchStream(ctx context.Context, ip netip.Addr, direction string, size int, round, stream int) (benchStreamResult, error) {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return n.server.Dial(ctx, network, net.JoinHostPort(ip.String(), "18080"))
		},
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		MaxIdleConnsPerHost:   1,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res := benchStreamResult{Round: round, Stream: stream, Bytes: size}
	url := "http://" + net.JoinHostPort(ip.String(), "18080") + "/bench-download?bytes=" + strconv.Itoa(size)
	if direction == "upload" {
		url = "http://" + net.JoinHostPort(ip.String(), "18080") + "/bench-upload"
	}
	start := time.Now()
	if direction == "download" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return res, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return res, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return res, fmt.Errorf("download status %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		res.SHA256, err = verifyPatternStream(resp.Body, size)
		if err != nil {
			return res, err
		}
		res.Bytes = size
	} else {
		wantSHA, err := hashPattern(size)
		if err != nil {
			return res, err
		}
		payload := &benchPatternReader{size: size}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, payload)
		if err != nil {
			return res, err
		}
		req.ContentLength = int64(size)
		resp, err := client.Do(req)
		if err != nil {
			return res, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return res, fmt.Errorf("upload status %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var bodyResp payloadResult
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&bodyResp); err != nil {
			return res, fmt.Errorf("decode upload body: %w", err)
		}
		if bodyResp.Bytes != size {
			return res, fmt.Errorf("upload length mismatch: got %d want %d", bodyResp.Bytes, size)
		}
		if bodyResp.SHA256 != wantSHA {
			return res, fmt.Errorf("upload sha mismatch: got %s want %s", bodyResp.SHA256, wantSHA)
		}
		res.SHA256 = bodyResp.SHA256
		res.Bytes = bodyResp.Bytes
	}
	res.DurationMS = time.Since(start).Milliseconds()
	if res.Bytes > 0 {
		res.Mbps = float64(res.Bytes*8) / (float64(res.DurationMS) / 1000) / 1e6
	}
	return res, nil
}

type benchPatternReader struct {
	size int
	off  int
	buf  [benchChunkSize]byte
}

func (r *benchPatternReader) Read(p []byte) (int, error) {
	if r.size == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.size {
		n = r.size
	}
	if n > len(r.buf) {
		n = len(r.buf)
	}
	fillPattern(r.buf[:n], r.off)
	copy(p, r.buf[:n])
	r.off += n
	r.size -= n
	return n, nil
}

func parseBenchRequest(r *http.Request) (benchParams, error) {
	q := r.URL.Query()
	params := benchParams{
		Target:    q.Get("target"),
		Bytes:     1 << 20,
		Parallel:  1,
		Direction: "download",
		Rounds:    1,
	}
	if q.Get("bytes") != "" {
		v, err := parseBenchSize(q.Get("bytes"))
		if err != nil {
			return params, err
		}
		params.Bytes = v
	}
	if q.Get("parallel") != "" {
		v, err := parseBenchParallel(q.Get("parallel"))
		if err != nil {
			return params, err
		}
		params.Parallel = v
	}
	if q.Get("direction") != "" {
		params.Direction = strings.ToLower(q.Get("direction"))
		if params.Direction != "download" && params.Direction != "upload" {
			return params, fmt.Errorf("direction must be download or upload")
		}
	}
	if q.Get("rounds") != "" {
		v, err := parseBenchRounds(q.Get("rounds"))
		if err != nil {
			return params, err
		}
		params.Rounds = v
	}
	if q.Get("warmup") != "" {
		v, err := strconv.Atoi(q.Get("warmup"))
		if err != nil || v < 0 || v > 3 {
			return params, fmt.Errorf("warmup must be 0..3")
		}
		params.Warmup = v
	}
	return params, nil
}

func parseBenchSize(v string) (int, error) {
	if v == "" {
		return 1 << 20, nil
	}
	size, err := strconv.Atoi(v)
	if err != nil || size < minBenchBytes || size > maxBenchBytes {
		return 0, fmt.Errorf("bytes must be between %d and %d", minBenchBytes, maxBenchBytes)
	}
	return size, nil
}

func parseBenchParallel(v string) (int, error) {
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > maxBenchParallel {
		return 0, fmt.Errorf("parallel must be between 1 and %d", maxBenchParallel)
	}
	return p, nil
}

func parseBenchRounds(v string) (int, error) {
	r, err := strconv.Atoi(v)
	if err != nil || r < 1 || r > maxBenchRounds {
		return 0, fmt.Errorf("rounds must be between 1 and %d", maxBenchRounds)
	}
	return r, nil
}

func ipInPeerStatus(st *ipnstate.Status, ip netip.Addr) bool {
	if st == nil {
		return false
	}
	for _, peer := range st.Peer {
		for _, peerIP := range peer.TailscaleIPs {
			if peerIP == ip {
				return true
			}
		}
	}
	return false
}

func hashPattern(size int) (string, error) {
	if size < minBenchBytes || size > maxBenchBytes {
		return "", fmt.Errorf("bytes must be between %d and %d", minBenchBytes, maxBenchBytes)
	}
	sha := sha256.New()
	buf := make([]byte, benchChunkSize)
	for offset := 0; offset < size; {
		chunk := min(len(buf), size-offset)
		fillPattern(buf[:chunk], offset)
		if _, err := sha.Write(buf[:chunk]); err != nil {
			return "", err
		}
		offset += chunk
	}
	return hex.EncodeToString(sha.Sum(nil)), nil
}

func fillPattern(dst []byte, offset int) {
	for i := range dst {
		dst[i] = byte((offset + i) % 251)
	}
}

func verifyPattern(data []byte, offset int) error {
	for i, b := range data {
		want := byte((offset + i) % 251)
		if b != want {
			return fmt.Errorf("payload mismatch at byte %d: got %d want %d", offset+i, b, want)
		}
	}
	return nil
}
