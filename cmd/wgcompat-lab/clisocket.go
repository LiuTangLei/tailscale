// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"tailscale.com/client/local"
)

// serveCLISocket bridges ONLY this lab's in-process LocalAPI to a private Unix
// socket for real CLI tests. It never binds a public TCP listener or connects to
// the production daemon. The socket must be inside the isolated state root.
func serveCLISocket(ctx context.Context, root, path string, lc *local.Client) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if filepath.Dir(path) != root {
		return nil, errors.New("CLI socket must be directly inside the isolated state directory")
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("CLI socket directory must be private (0700)")
	}
	// Never delete an existing socket that may belong to another running lab.
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/localapi/v0/") {
			http.NotFound(w, r)
			return
		}
		req := r.Clone(r.Context())
		u := *r.URL
		req.URL = &u
		req.URL.Scheme = "http"
		req.URL.Host = "local-tailscaled.sock"
		req.Host = "local-tailscaled.sock"
		req.RequestURI = ""
		res, err := lc.DoLocalRequest(req)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer res.Body.Close()
		for k, vs := range res.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(res.StatusCode)
		io.Copy(w, res.Body)
	})}
	go server.Serve(ln)
	stop := context.AfterFunc(ctx, func() { server.Close() })
	return func() { stop(); server.Close() }, nil
}
