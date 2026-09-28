package main

import (
	"net/http"
	"runtime/pprof"
	"strconv"
	"time"
)

// cpuProfile belongs only to the loopback diagnostic server of wgcompat-lab.
// No public listener is added; the outer admin handler rejects browser origins
// and requires its custom header for POST. Profiles are bounded and contain
// sampled function stacks, not packet payloads or session keys.
func cpuProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("X-WG-Lab") != "1" {
		http.Error(w, "local POST required", 405)
		return
	}
	seconds, err := strconv.Atoi(r.URL.Query().Get("seconds"))
	if err != nil || seconds < 3 || seconds > 30 {
		http.Error(w, "seconds must be 3..30", 400)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if err := pprof.StartCPUProfile(w); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	defer pprof.StopCPUProfile()
	timer := time.NewTimer(time.Duration(seconds) * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-r.Context().Done():
	}
}
