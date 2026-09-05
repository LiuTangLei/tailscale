package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"testing"
)

func TestFillPatternAcrossChunkBoundaries(t *testing.T) {
	size := benchChunkSize*2 + 17
	buf := make([]byte, size)
	fillPattern(buf, 0)
	for i := range buf {
		want := byte(i % 251)
		if buf[i] != want {
			t.Fatalf("byte %d = %d want %d", i, buf[i], want)
		}
	}
	for off := 0; off < size; off += benchChunkSize {
		end := off + benchChunkSize
		if end > size {
			end = size
		}
		if err := verifyPattern(buf[off:end], off); err != nil {
			t.Fatalf("verify chunk %d..%d: %v", off, end, err)
		}
	}
}

func TestBenchDownloadAndUploadHandlers(t *testing.T) {
	size := 128 << 10
	getReq := httptest.NewRequest(http.MethodGet, "/bench-download?bytes="+strconv.Itoa(size), nil)
	getRec := httptest.NewRecorder()
	benchDownloadHandler(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /bench-download = %d %s", getRec.Code, getRec.Body.String())
	}
	if got := len(getRec.Body.Bytes()); got != size {
		t.Fatalf("download len = %d want %d", got, size)
	}
	if err := verifyPattern(getRec.Body.Bytes(), 0); err != nil {
		t.Fatalf("download pattern mismatch: %v", err)
	}

	body := make([]byte, size)
	fillPattern(body, 0)
	postReq := httptest.NewRequest(http.MethodPost, "/bench-upload", bytes.NewReader(body))
	postRec := httptest.NewRecorder()
	benchUploadHandler(postRec, postReq)
	if postRec.Code != http.StatusOK {
		t.Fatalf("POST /bench-upload = %d %s", postRec.Code, postRec.Body.String())
	}
	var got payloadResult
	if err := json.Unmarshal(postRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode upload result: %v", err)
	}
	if got.Bytes != size {
		t.Fatalf("upload bytes = %d want %d", got.Bytes, size)
	}
	if got.SHA256 != digest(body) {
		t.Fatalf("upload sha = %s want %s", got.SHA256, digest(body))
	}
}

func TestBenchRequestParsingAndLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		kind string
	}{
		{name: "download small", url: "/bench-download?bytes=0", kind: "download"},
		{name: "download large", url: "/bench-download?bytes=300000000", kind: "download"},
		{name: "invalid parallel", url: "/bench?target=100.64.0.1&parallel=0", kind: "parse"},
		{name: "invalid rounds", url: "/bench?target=100.64.0.1&rounds=9", kind: "parse"},
		{name: "invalid direction", url: "/bench?target=100.64.0.1&direction=sideways", kind: "parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.kind == "download" {
				req := httptest.NewRequest(http.MethodGet, tc.url, nil)
				rec := httptest.NewRecorder()
				benchDownloadHandler(rec, req)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("code = %d want %d", rec.Code, http.StatusBadRequest)
				}
				return
			}
			req := httptest.NewRequest(http.MethodPost, tc.url, nil)
			if _, err := parseBenchRequest(req); err == nil {
				t.Fatalf("expected parse error for %q", tc.url)
			}
		})
	}
}

func TestMetricsSnapshot(t *testing.T) {
	m := metricsSnapshot()
	if m.Goroutines <= 0 {
		t.Fatal("goroutines metric missing")
	}
	if m.MemAllocBytes <= 0 {
		t.Fatal("mem alloc metric missing")
	}
	if runtime.GOOS == "linux" && m.RSSBytes <= 0 {
		t.Fatal("RSS metric missing on linux")
	}
}
