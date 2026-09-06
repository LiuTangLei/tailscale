// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// wgcompat-lab exercises the actual Tailscale engine in isolated tsnet nodes.
// It is a DEVELOPMENT TEST PROGRAM, not a production control server or daemon.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/wgengine/wgtransport"
	"tailscale.com/wgengine/wgtransport/quicbind"
)

const maxPayload = 4 << 20

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: wgcompat-lab control|node [flags]")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	fs := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:18440", "loopback control/admin address")
	derpListen := fs.String("derp-listen", "127.0.0.1:18442", "loopback-only isolated DERP TLS address (control command)")
	publicSTUN := fs.Bool("public-stun", false, "add public Tailscale STUN probes to the isolated relay map")
	privateSTUN := fs.String("stun-server", "", "literal test STUN IPv4:port instead of an external server list")
	stunListen := fs.String("stun-listen", "", "optional isolated test STUN UDP listener (node command)")
	control := fs.String("control", "http://127.0.0.1:18440", "isolated test control URL")
	dir := fs.String("dir", "", "isolated node state directory (required for node)")
	cliSocket := fs.String("localapi-socket", "", "optional private Unix socket inside --dir for actual CLI tests")
	hostname := fs.String("hostname", "wgcompat-lab", "test node hostname")
	port := fs.Uint("port", 42641, "test node UDP port, separate from production")
	profileName := fs.String("profile", "standard", "standard|awg2|awg3|awg31")
	kernelNamespace := fs.String("kernel-netns", "", "Linux test-only qbench-* namespace containing the kernel TUN; outer sockets remain on host")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	if os.Args[1] == "identity" {
		return generateIdentity(*dir)
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if err := requireLoopback(*listen); err != nil {
		return err
	}
	if *port == 0 || *port > 65535 {
		return errors.New("invalid UDP port")
	}
	if os.Args[1] == "control" {
		derpMap, closeDERP, err := startLabDERP(*derpListen, log.Printf)
		if err != nil {
			return err
		}
		defer closeDERP()
		if *privateSTUN != "" {
			if err := attachPrivateSTUN(derpMap, *privateSTUN); err != nil {
				return err
			}
		} else if *publicSTUN {
			if err := addPublicSTUN(ctx, derpMap); err != nil {
				return err
			}
		}
		c := &testcontrol.Server{ExplicitBaseURL: "http://" + *listen, AllNodesSameUser: true, AllOnline: true, DERPMap: derpMap, Logf: log.Printf}
		return serve(ctx, *listen, c)
	}
	if os.Args[1] != "node" {
		return errors.New("unknown command")
	}
	if *dir == "" {
		return errors.New("node requires a separate --dir")
	}
	closeSTUN, err := startPrivateSTUN(ctx, *stunListen)
	if err != nil {
		return err
	}
	defer closeSTUN()
	p, err := profile(*profileName)
	if err != nil {
		return err
	}
	s := &tsnet.Server{Dir: *dir, Hostname: *hostname, ControlURL: *control, Port: uint16(*port), Logf: log.Printf, UserLogf: log.Printf}
	var quicFactory *quicbind.Factory
	var reconnectFactory *labReconnectFactory
	if mode := os.Getenv("TS_EXPERIMENTAL_WG_TRANSPORT"); mode == "quic" || mode == "quic-ip" || mode == "http3-ip" {
		quicFactory, err = quicbind.Load(os.Getenv("TS_EXPERIMENTAL_QUIC_CONFIG"))
		if err != nil {
			return err
		}
		reconnectFactory = &labReconnectFactory{factory: quicFactory}
		s.Transport = wgtransport.Config{Mode: wgtransport.Mode(mode), Factory: reconnectFactory}
	}
	if *kernelNamespace != "" {
		s.Tun, err = openKernelBenchTUN(*kernelNamespace)
		if err != nil {
			return err
		}
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return err
	}
	lc, err := s.LocalClient()
	if err != nil {
		return err
	}
	startup, startupCancel := context.WithTimeout(ctx, 60*time.Second)
	defer startupCancel()
	if _, err := lc.EditPrefs(startup, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AmneziaWG: p}, AmneziaWGSet: true}); err != nil {
		return err
	}
	if _, err := s.Up(startup); err != nil {
		return fmt.Errorf("bring up test node: %w", err)
	}
	closeCLI, err := serveCLISocket(ctx, *dir, *cliSocket, lc)
	if err != nil {
		return err
	}
	defer closeCLI()
	ln, err := s.Listen("tcp", ":18080")
	if err != nil {
		return err
	}
	tailnetMux := http.NewServeMux()
	tailnetMux.HandleFunc("/payload", payloadHandler)
	registerTailnetHandlers(tailnetMux)
	dataServer := &http.Server{Handler: tailnetMux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 45 * time.Second}
	defer dataServer.Close()
	go func() {
		if err := dataServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("payload server: %v", err)
		}
	}()
	n := &node{server: s, lc: lc, profile: *profileName}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", n.status)
	mux.HandleFunc("/profile", n.setProfile)
	mux.HandleFunc("/probe", n.probe)
	mux.HandleFunc("/reconnect", reconnectFactory.serve)
	registerAdminHandlers(mux, n)
	mux.HandleFunc("/quic", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		stats, err := s.PacketTransportDiagnostics()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, stats)
	})
	return serve(ctx, *listen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No browser-origin requests or CORS. Mutations need a custom header.
		if r.Header.Get("Origin") != "" || (r.Method != "GET" && r.Header.Get("X-WG-Lab") != "1") {
			http.Error(w, "local test client required", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

func requireLoopback(addr string) error {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(h)
	if err != nil || !ip.IsLoopback() {
		return errors.New("test control/admin listeners must bind a literal loopback IP")
	}
	return nil
}

func serve(ctx context.Context, addr string, h http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdown); err != nil {
			s.Close()
			return err
		}
		return nil
	}
}

func profile(name string) (ipn.AmneziaWGPrefs, error) {
	if name == "standard" {
		return ipn.AmneziaWGPrefs{}, nil
	}
	p := ipn.AmneziaWGPrefs{JC: 2, JMin: 64, JMax: 128, S1: 20, S2: 24, S3: 16,
		H1: ipn.MagicHeaderRange{Min: 100001, Max: 100001}, H2: ipn.MagicHeaderRange{Min: 200002, Max: 200002},
		H3: ipn.MagicHeaderRange{Min: 300003, Max: 300003}, H4: ipn.MagicHeaderRange{Min: 400004, Max: 400004}}
	switch name {
	case "awg2":
	case "awg3", "awg31":
		p.S4 = 16
		// Public deterministic TEST profile. Never a WireGuard private key.
		p.HeaderProtectionKey = strings.Repeat("12", 32)
		p.ContentPaddingAddition = ipn.MagicHeaderRange{Min: 0, Max: 16}
		if name == "awg31" {
			p.RandomTrailers = true
			p.DisableCookies = true
		}
	default:
		return ipn.AmneziaWGPrefs{}, fmt.Errorf("unknown test profile %q", name)
	}
	return p, ipn.ValidateAmneziaWGConfig(p)
}

type node struct {
	opMu    sync.Mutex // exclusive probes/benchmarks/profile changes; status stays readable
	server  *tsnet.Server
	lc      *local.Client
	mu      sync.Mutex // serialize probes/profile updates, not the data server
	profile string
}

type peerInfo struct {
	Name                   string       `json:"name"`
	IPs                    []netip.Addr `json:"ips"`
	Online                 bool         `json:"online"`
	Direct                 string       `json:"direct"`
	Relay                  string       `json:"relay"`
	Tx, Rx                 int64
	LastHandshake          time.Time `json:"lastHandshake"`
	SessionProtocol        string    `json:"session_protocol,omitempty"`
	LastSessionEstablished time.Time `json:"last_session_established"`
	SessionState           uint8     `json:"session_state"`
}
type statusResult struct {
	PublicKey string       `json:"public_key"`
	State     string       `json:"state"`
	Profile   string       `json:"profile"`
	IPs       []netip.Addr `json:"ips"`
	Peers     []peerInfo   `json:"peers"`
}

func snapshot(st *ipnstate.Status, name string) statusResult {
	r := statusResult{State: st.BackendState, Profile: name, IPs: st.TailscaleIPs}
	if st.Self != nil {
		r.PublicKey = st.Self.PublicKey.String()
	}
	for _, p := range st.Peer {
		r.Peers = append(r.Peers, peerInfo{Name: p.HostName, IPs: p.TailscaleIPs, Online: p.Online, Direct: p.CurAddr, Relay: p.Relay, Tx: p.TxBytes, Rx: p.RxBytes, LastHandshake: p.LastHandshake, SessionProtocol: p.SessionProtocol, LastSessionEstablished: p.LastSessionEstablished, SessionState: p.SessionState})
	}
	return r
}
func (n *node) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "GET required", 405)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	st, err := n.lc.Status(ctx)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	n.mu.Lock()
	name := n.profile
	n.mu.Unlock()
	writeJSON(w, snapshot(st, name))
}
func (n *node) setProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	p, err := profile(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if !n.opMu.TryLock() {
		http.Error(w, "operation in progress", 409)
		return
	}
	defer n.opMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := n.lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AmneziaWG: p}, AmneziaWGSet: true}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	n.mu.Lock()
	n.profile = r.URL.Query().Get("name")
	n.mu.Unlock()
	writeJSON(w, map[string]any{"profile": n.profile, "applied": true})
}

func payload(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type payloadResult struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

func payloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/payload" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case "GET":
		size, err := strconv.Atoi(r.URL.Query().Get("size"))
		if err != nil || size < 1 || size > maxPayload {
			http.Error(w, "invalid size", 400)
			return
		}
		b := payload(size)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Write(b)
	case "POST":
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPayload))
		if err != nil || len(b) == 0 {
			http.Error(w, "invalid body", 400)
			return
		}
		writeJSON(w, payloadResult{len(b), digest(b)})
	default:
		http.Error(w, "GET or POST required", 405)
	}
}

type probeResult struct {
	Target   string               `json:"target"`
	Profile  string               `json:"profile"`
	Disco    *ipnstate.PingResult `json:"discovery"`
	TSMP     *ipnstate.PingResult `json:"tsmp"`
	Download payloadResult        `json:"download"`
	Upload   payloadResult        `json:"upload"`
	Seconds  float64              `json:"seconds"`
	Status   statusResult         `json:"status"`
}

func (n *node) probe(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	if !n.opMu.TryLock() {
		http.Error(w, "operation in progress", 409)
		return
	}
	defer n.opMu.Unlock()
	ip, err := netip.ParseAddr(r.URL.Query().Get("target"))
	if err != nil {
		http.Error(w, "invalid target", 400)
		return
	}
	size := 1 << 20
	if s := r.URL.Query().Get("size"); s != "" {
		size, err = strconv.Atoi(s)
	}
	if err != nil || size < 1 || size > maxPayload {
		http.Error(w, "invalid size", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	st, err := n.lc.Status(ctx)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	known := false
	for _, p := range st.Peer {
		for _, addr := range p.TailscaleIPs {
			known = known || addr == ip
		}
	}
	if !known {
		http.Error(w, "target is not a known test peer", 400)
		return
	}
	result := probeResult{Target: ip.String(), Profile: n.profile}
	started := time.Now()
	// Discovery may be used to select a path, but is never the data-plane proof.
	for i := 0; i < 4; i++ {
		pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
		result.Disco, _ = n.lc.Ping(pingCtx, ip, tailcfg.PingDisco)
		pingCancel()
		if result.Disco != nil && result.Disco.Err == "" && result.Disco.Endpoint != "" {
			break
		}
		select {
		case <-ctx.Done():
			http.Error(w, ctx.Err().Error(), 504)
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
	result.TSMP, err = n.lc.Ping(ctx, ip, tailcfg.PingTSMP)
	if err != nil {
		http.Error(w, "encrypted TSMP: "+err.Error(), 504)
		return
	}
	if result.TSMP == nil || result.TSMP.Err != "" {
		http.Error(w, fmt.Sprintf("encrypted TSMP failed: %+v", result.TSMP), 504)
		return
	}
	tr := &http.Transport{DialContext: n.server.Dial, DisableKeepAlives: true, Proxy: nil, ResponseHeaderTimeout: 30 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	url := "http://" + net.JoinHostPort(ip.String(), "18080") + "/payload"
	get, _ := http.NewRequestWithContext(ctx, "GET", url+"?size="+strconv.Itoa(size), nil)
	res, err := client.Do(get)
	if err != nil {
		http.Error(w, "download: "+err.Error(), 502)
		return
	}
	b, readErr := io.ReadAll(io.LimitReader(res.Body, int64(size)+1))
	res.Body.Close()
	want := payload(size)
	if readErr != nil || res.StatusCode != 200 || !bytes.Equal(b, want) {
		http.Error(w, fmt.Sprintf("download verification failed: status=%d bytes=%d want=%d read=%v", res.StatusCode, len(b), size, readErr), 502)
		return
	}
	result.Download = payloadResult{len(b), digest(b)}
	post, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(want))
	res, err = client.Do(post)
	if err != nil {
		http.Error(w, "upload: "+err.Error(), 502)
		return
	}
	err = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&result.Upload)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || result.Upload.Bytes != size || result.Upload.SHA256 != digest(want) {
		http.Error(w, "upload payload verification failed", 502)
		return
	}
	result.Seconds = time.Since(started).Seconds()
	st, err = n.lc.Status(ctx)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	result.Status = snapshot(st, n.profile)
	writeJSON(w, result)
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
