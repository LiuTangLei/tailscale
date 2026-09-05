// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

func TestStreamingValidation(t *testing.T) {
	const size = 3*benchChunkSize + 17
	data := payload(size)
	got, err := verifyPatternStream(bytes.NewReader(data), size)
	if err != nil || got != digest(data) {
		t.Fatalf("hash=%s err=%v", got, err)
	}
	for _, bad := range [][]byte{data[:size-1], append(append([]byte{}, data...), 0)} {
		if _, err := verifyPatternStream(bytes.NewReader(bad), size); err == nil {
			t.Fatal("accepted wrong length")
		}
	}
	data[benchChunkSize+5] ^= 1
	if _, err := verifyPatternStream(bytes.NewReader(data), size); err == nil {
		t.Fatal("accepted corrupted data")
	}
}
func TestBenchmarkWarmupBound(t *testing.T) {
	req := httptest.NewRequest("POST", "/bench?warmup=1000000", nil)
	if _, err := parseBenchRequest(req); err == nil {
		t.Fatal("unbounded warmup")
	}
}
