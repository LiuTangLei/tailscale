// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func authenticatedTicketState(t *testing.T) *tls.SessionState {
	t.Helper()
	pair := newTestPair(t, "http3-magicsock", func(c *Config) { c.AutoTrust = true; c.Peers = nil })
	pair.open(t)
	remote := pair.keys[1].Public().Raw32()
	p, err := pair.backends[0].active.Load().peer(remote, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.getSession(); err != nil {
		t.Fatal(err)
	}
	waitTicket(t, pair.backends[0].clientSessionCache(remote))
	s := pair.backends[1].tickets.Load()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ticket := range s.tickets {
		state, err := tls.ParseSessionState(ticket.State)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	t.Fatal("missing authenticated server state")
	return nil
}

func TestSingleUseTicketJournal(t *testing.T) {
	state := authenticatedTicketState(t)
	identity := resumeIdentity{Local: [32]byte{1}, Peer: [32]byte{2}, Pin: [32]byte{3}}
	scope := [32]byte{4}
	open := func(t *testing.T, path string) *serverTicketStore {
		t.Helper()
		s, e := openServerTicketStore(path, scope)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(s.close)
		return s
	}
	t.Run("concurrent_replay_and_restart", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tickets")
		s := open(t, path)
		used, e := s.issue(identity, state)
		if e != nil {
			t.Fatal(e)
		}
		unused, e := s.issue(identity, state)
		if e != nil {
			t.Fatal(e)
		}
		var accepted atomic.Int32
		var workers sync.WaitGroup
		for range 32 {
			workers.Go(func() {
				if got, id := s.take(used); got != nil {
					if id != identity {
						t.Error("identity changed")
					}
					accepted.Add(1)
				}
			})
		}
		workers.Wait()
		if accepted.Load() != 1 {
			t.Fatalf("accepted replay %d times", accepted.Load())
		}
		if _, e := openServerTicketStore(path, scope); e == nil {
			t.Fatal("second writer acquired journal")
		}
		s.close()
		s = open(t, path)
		if got, _ := s.take(used); got != nil {
			t.Fatal("consumed ticket survived restart")
		}
		if got, id := s.take(unused); got == nil || id != identity {
			t.Fatal("unused ticket did not survive restart")
		}
		s.close()
		s = open(t, path)
		if got, _ := s.take(unused); got != nil {
			t.Fatal("second consumed ticket survived restart")
		}
	})
	t.Run("expiry_revocation_scope", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tickets")
		s := open(t, path)
		id, _ := s.issue(identity, state)
		s.revoke(identity.Peer)
		s.close()
		s = open(t, path)
		if got, _ := s.take(id); got != nil {
			t.Fatal("revoked ticket accepted")
		}
		id, _ = s.issue(identity, state)
		s.mu.Lock()
		for k, v := range s.tickets {
			v.Expires = time.Now().Add(-time.Second).Unix()
			s.tickets[k] = v
		}
		s.mu.Unlock()
		if got, _ := s.take(id); got != nil {
			t.Fatal("expired ticket accepted")
		}
		id, _ = s.issue(identity, state)
		s.close()
		different, e := openServerTicketStore(path, [32]byte{5})
		if e != nil {
			t.Fatal(e)
		}
		defer different.close()
		if got, _ := different.take(id); got != nil {
			t.Fatal("ticket crossed configuration scope")
		}
	})
	t.Run("torn_journal_and_write_failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tickets")
		s := open(t, path)
		id, _ := s.issue(identity, state)
		s.mu.Lock()
		s.file.Close()
		s.mu.Unlock()
		if got, _ := s.take(id); got != nil {
			t.Fatal("ticket accepted before durable consumption")
		}
		if !s.disabled {
			t.Fatal("journal I/O failure did not disable acceptance")
		}
		s.close()
		f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		f.WriteString("partial take")
		f.Close()
		if s, e := openServerTicketStore(path, scope); e == nil {
			s.close()
			t.Fatal("torn journal was accepted")
		}
	})
	t.Run("bounded_and_private", func(t *testing.T) {
		s := newMemoryTicketStore()
		defer s.close()
		first, _ := s.issue(identity, state)
		for range maxResumptionTickets {
			if _, e := s.issue(identity, state); e != nil {
				t.Fatal(e)
			}
		}
		if len(s.tickets) != maxResumptionTickets || len(s.order) != maxResumptionTickets {
			t.Fatal("unbounded ticket store")
		}
		if got, _ := s.take(first); got != nil {
			t.Fatal("evicted ticket accepted")
		}
		path := filepath.Join(t.TempDir(), "public")
		os.WriteFile(path, []byte("private state"), 0644)
		if s, e := openServerTicketStore(path, scope); e == nil {
			s.close()
			t.Fatal("public journal accepted")
		}
	})
}
