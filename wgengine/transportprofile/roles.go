// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package transportprofile

import (
	"errors"
	"slices"

	"tailscale.com/ipn"
)

func (p Profile) validateRoles() error {
	for k, role := range p.HTTP3PeerRoles {
		canonical, err := canonicalKey(k)
		if err != nil || canonical != k {
			return errors.New("HTTP/3 role map requires canonical peer public keys")
		}
		if !slices.ContainsFunc(p.Peers, func(peer ipn.TransportPeer) bool { return peer.PublicKey == k }) {
			return errors.New("HTTP/3 role map contains an untrusted or removed peer")
		}
		switch role {
		case "mesh", "client", "server":
		default:
			return errors.New("HTTP/3 role must be mesh, client or server")
		}
	}
	return nil
}
