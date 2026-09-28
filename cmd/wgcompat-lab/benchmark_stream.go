// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// Stream validation uses a constant 64 KiB buffer; benchmark payload size must
// not turn into a giant allocation that distorts transport CPU/GC measurements.
func verifyPatternStream(r io.Reader, size int) (string, error) {
	hash := sha256.New()
	buf := make([]byte, benchChunkSize)
	reader := io.LimitReader(r, int64(size)+1)
	offset := 0
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if offset+n > size {
				return "", fmt.Errorf("download exceeds expected length %d", size)
			}
			if e := verifyPattern(buf[:n], offset); e != nil {
				return "", e
			}
			hash.Write(buf[:n])
			offset += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if offset != size {
		return "", fmt.Errorf("download length %d, expected %d", offset, size)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
