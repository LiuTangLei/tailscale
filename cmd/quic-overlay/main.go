// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// quic-overlay writes a version-checked Go build overlay for the small HTTP/3
// receive-queue patch. It never modifies Go's shared module cache. The overlay
// and ts_http3_queue_overlay tag must be used together by distribution builds.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const modulePath = "github.com/quic-go/quic-go"
const version = "v0.62.0"
const moduleSum = "h1:ZHDjCk5OacATwGvs8PWE97CTvX7AqZiVoW7++ZOXTf8="
const upstreamSHA256 = "be09304f3946cb700489d150ffdd3a231ed05e674fa5bef240b54d2e48c014da"

type moduleInfo struct {
	Path, Version, Dir, Sum string
	Replace                 *moduleInfo
}

func main() {
	out := flag.String("output", "", "output JSON path; otherwise a temporary file")
	root := flag.String("root", ".", "root of this Tailscale source tree")
	flag.Parse()
	if err := run(*root, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root, output string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	cmd := exec.Command("go", "list", "-m", "-json", modulePath)
	cmd.Dir = root
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("query pinned QUIC module: %w", err)
	}
	var m moduleInfo
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m.Path != modulePath || m.Version != version || m.Sum != moduleSum || m.Replace != nil || m.Dir == "" {
		return errors.New("QUIC overlay requires the exact unmodified quic-go v0.62.0 module; re-review the patch before upgrading")
	}
	// Go forbids overlays under its active GOMODCACHE. Download the same
	// checksum-verified public module into a separate build cache and use an
	// alternate modfile for this invocation only; project go.mod stays intact.
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	cache = filepath.Join(cache, "tailscale-http3-build", "modules")
	download := exec.Command("go", "mod", "download", "-json", modulePath+"@"+version)
	download.Dir = root
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GOMODCACHE=") && !strings.HasPrefix(value, "GOTOOLCHAIN=") {
			download.Env = append(download.Env, value)
		}
	}
	download.Env = append(download.Env, "GOMODCACHE="+cache, "GOTOOLCHAIN=local")
	data, err = download.Output()
	if err != nil {
		return fmt.Errorf("download isolated public QUIC source: %w", err)
	}
	var isolated moduleInfo
	if err := json.Unmarshal(data, &isolated); err != nil {
		return err
	}
	if isolated.Version != version || isolated.Sum != moduleSum || isolated.Dir == "" {
		return errors.New("isolated QUIC module checksum mismatch")
	}
	m.Dir = isolated.Dir
	original := filepath.Join(m.Dir, "http3", "state_tracking_stream.go")
	source, err := os.ReadFile(original)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(source)
	if hex.EncodeToString(hash[:]) != upstreamSHA256 {
		return errors.New("upstream HTTP/3 source checksum changed; refusing to apply stale overlay")
	}
	files := map[string]string{}
	for _, name := range []string{"state_tracking_stream.go", "state_tracking_stream_tunnel_test.go"} {
		patched := filepath.Join(root, "third_party", "quic-go-overlay", name+".txt")
		if _, err := os.Stat(patched); err != nil {
			return err
		}
		files[filepath.Join(m.Dir, "http3", name)] = patched
	}
	var f *os.File
	if output == "" {
		f, err = os.CreateTemp("", "tailscale-http3-overlay-*.json")
	} else {
		f, err = os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	}
	if err != nil {
		return err
	}
	// -modfile only changes dependency resolution; the main source remains
	// this working tree. Relative paths in the temporary files never enter git.
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		f.Close()
		return err
	}
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		f.Close()
		return err
	}
	modPath := f.Name() + ".mod"
	if err := os.WriteFile(modPath, mod, 0600); err != nil {
		f.Close()
		return err
	}
	if err := os.WriteFile(f.Name()+".sum", sum, 0600); err != nil {
		f.Close()
		return err
	}
	edit := exec.Command("go", "mod", "edit", "-modfile="+modPath, "-replace="+modulePath+"="+m.Dir)
	edit.Dir = root
	if data, err := edit.CombinedOutput(); err != nil {
		f.Close()
		return fmt.Errorf("prepare isolated modfile: %w: %s", err, data)
	}
	encErr := json.NewEncoder(f).Encode(struct{ Replace map[string]string }{files})
	closeErr := f.Close()
	if err := errors.Join(encErr, closeErr); err != nil {
		return err
	}
	path, err := filepath.Abs(f.Name())
	if err != nil {
		return err
	}
	fmt.Println(path)
	return nil
}
