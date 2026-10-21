// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package quicbind

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"tailscale.com/atomicfile"
)

const maxResumptionTickets = 4096
const resumptionLifetime = 24 * time.Hour
const ticketJournalMagic = "tailscale-h3-single-use-tickets-v1 "

type resumeIdentity struct {
	Local [32]byte `json:"local"`
	Peer  [32]byte `json:"peer"`
	Pin   [32]byte `json:"pin"`
}
type storedTicket struct {
	Identity resumeIdentity `json:"identity"`
	Expires  int64          `json:"expires"`
	State    []byte         `json:"state"`
}
type ticketRecord struct {
	Operation string        `json:"op"`
	ID        string        `json:"id"`
	Ticket    *storedTicket `json:"ticket,omitempty"`
}
type serverTicketStore struct {
	mu           sync.Mutex
	tickets      map[string]storedTicket
	order        []string
	file         *os.File
	lock         *flock.Flock
	path         string
	scope        [32]byte
	records      int
	journalBytes int64
	disabled     bool
}

func newMemoryTicketStore() *serverTicketStore {
	return &serverTicketStore{tickets: make(map[string]storedTicket)}
}
func openServerTicketStore(path string, scope [32]byte) (_ *serverTicketStore, err error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("ticket journal must use an absolute path")
	}
	for _, name := range []string{path, path + ".lock"} {
		st, e := os.Lstat(name)
		if e == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
			return nil, errors.New("ticket journal and lock must be private regular files")
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	lock := flock.New(path+".lock", flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, errors.New("ticket journal is already in use")
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	store := newMemoryTicketStore()
	store.path, store.scope, store.lock = path, scope, lock
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		st, e := file.Stat()
		if e != nil {
			return nil, e
		}
		if st.Size() > 256<<20 {
			return nil, errors.New("ticket journal exceeds size bound")
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 256<<20))
		scanner.Buffer(make([]byte, 4096), 64<<10)
		if !scanner.Scan() {
			return nil, errors.New("empty ticket journal")
		}
		header := scanner.Text()
		prefix := ticketJournalMagic
		if len(header) != len(prefix)+64 || header[:len(prefix)] != prefix {
			return nil, errors.New("invalid ticket journal header")
		}
		if header == prefix+hex.EncodeToString(scope[:]) {
			for scanner.Scan() {
				line := scanner.Bytes()
				if len(line) < 65 || line[64] != ' ' {
					return nil, errors.New("incomplete ticket journal record")
				}
				sum := sha256.Sum256(line[65:])
				if !bytes.Equal(line[:64], []byte(hex.EncodeToString(sum[:]))) {
					return nil, errors.New("ticket journal checksum mismatch")
				}
				var record ticketRecord
				if json.Unmarshal(line[65:], &record) != nil || len(record.ID) != 64 {
					return nil, errors.New("invalid ticket journal record")
				}
				switch record.Operation {
				case "issue":
					if record.Ticket == nil || len(record.Ticket.State) > 16<<10 {
						return nil, errors.New("invalid stored ticket")
					}
					store.tickets[record.ID] = *record.Ticket
					store.order = append(store.order, record.ID)
				case "take":
					delete(store.tickets, record.ID)
				default:
					return nil, errors.New("unknown ticket journal operation")
				}
				store.evictLocked(time.Now())
			}
			if err := scanner.Err(); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err = store.rewriteLocked(); err != nil {
		return nil, err
	}
	return store, nil
}
func encodeTicketRecord(record ticketRecord) []byte {
	data, _ := json.Marshal(record)
	sum := sha256.Sum256(data)
	result := append([]byte(hex.EncodeToString(sum[:])+" "), data...)
	return append(result, '\n')
}
func (s *serverTicketStore) evictLocked(now time.Time) {
	fresh := s.order[:0]
	for _, id := range s.order {
		ticket, ok := s.tickets[id]
		if !ok {
			continue
		}
		if ticket.Expires <= now.Unix() {
			delete(s.tickets, id)
			continue
		}
		fresh = append(fresh, id)
	}
	s.order = fresh
	for len(s.order) > maxResumptionTickets {
		delete(s.tickets, s.order[0])
		s.order = s.order[1:]
	}
}
func (s *serverTicketStore) rewriteLocked() error {
	s.evictLocked(time.Now())
	data := []byte(ticketJournalMagic + hex.EncodeToString(s.scope[:]) + "\n")
	for _, id := range s.order {
		ticket := s.tickets[id]
		data = append(data, encodeTicketRecord(ticketRecord{"issue", id, &ticket})...)
	}
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
	if err := atomicfile.WriteFile(s.path, data, 0600); err != nil {
		return err
	}
	// Without a durable rename a later take could disappear after a crash.
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	s.file, err = os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0600)
	s.records = len(s.order)
	s.journalBytes = int64(len(data))
	return err
}
func (s *serverTicketStore) appendLocked(record ticketRecord, durable bool) bool {
	if s.disabled {
		return false
	}
	if s.path == "" {
		return true
	}
	if s.file == nil {
		return false
	}
	recordBytes := encodeTicketRecord(record)
	n, err := s.file.Write(recordBytes)
	if err == nil && n != len(recordBytes) {
		err = io.ErrShortWrite
	}
	s.journalBytes += int64(n)
	if err == nil && durable {
		err = s.file.Sync()
	}
	if err != nil {
		s.disabled = true
		clear(s.tickets)
		return false
	}
	s.records++
	if s.records > maxResumptionTickets*4 || s.journalBytes > 128<<20 {
		if s.rewriteLocked() != nil {
			s.disabled = true
			clear(s.tickets)
			return false
		}
	}
	return true
}
func (s *serverTicketStore) issue(identity resumeIdentity, state *tls.SessionState) ([]byte, error) {
	data, err := state.Bytes()
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<10 {
		return nil, errors.New("TLS session state exceeds ticket bound")
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	name := hex.EncodeToString(id[:])
	ticket := storedTicket{identity, time.Now().Add(resumptionLifetime).Unix(), data}
	s.mu.Lock()
	defer s.mu.Unlock()
	// An issue lost before a crash only causes a full handshake. A take must
	// become durable before TLS is allowed to use the associated PSK.
	if s.appendLocked(ticketRecord{"issue", name, &ticket}, false) {
		s.tickets[name] = ticket
		s.order = append(s.order, name)
		s.evictLocked(time.Now())
	}
	return id[:], nil
}
func (s *serverTicketStore) take(id []byte) (*tls.SessionState, resumeIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var zero resumeIdentity
	if len(id) != 32 || s.disabled {
		return nil, zero
	}
	name := hex.EncodeToString(id)
	ticket, ok := s.tickets[name]
	if !ok {
		return nil, zero
	}
	delete(s.tickets, name)
	if !s.appendLocked(ticketRecord{Operation: "take", ID: name}, true) || ticket.Expires <= time.Now().Unix() {
		return nil, zero
	}
	state, err := tls.ParseSessionState(ticket.State)
	if err != nil {
		return nil, zero
	}
	return state, ticket.Identity
}
func (s *serverTicketStore) revoke(peer [32]byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dirty := false
	for id, ticket := range s.tickets {
		if peer != ([32]byte{}) && ticket.Identity.Peer != peer {
			continue
		}
		delete(s.tickets, id)
		if !s.appendLocked(ticketRecord{Operation: "take", ID: id}, false) {
			return
		}
		dirty = true
	}
	// One durable flush covers the whole revocation while the store is locked;
	// bulk identity rotation must not perform thousands of synchronous writes.
	if dirty && s.file != nil {
		if err := s.file.Sync(); err != nil {
			s.disabled = true
			clear(s.tickets)
		}
	}
}
func (s *serverTicketStore) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disabled = true
	clear(s.tickets)
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
	if s.lock != nil {
		s.lock.Close()
		s.lock = nil
	}
}
func (s *serverTicketStore) snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{"persistent": s.path != "", "disabled": s.disabled, "available": len(s.tickets)}
}

// Each cache belongs to one local backend and one exact peer, including peers
// with no SNI. Never key private Tailnet sessions by an address or shared name.
type peerSessionCache struct {
	mu     sync.Mutex
	ticket *tls.ClientSessionState
}

func (c *peerSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ticket := c.ticket
	c.ticket = nil
	return ticket, ticket != nil
}
func (c *peerSessionCache) Put(_ string, ticket *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ticket = ticket
}
func (c *peerSessionCache) clear() { c.mu.Lock(); defer c.mu.Unlock(); c.ticket = nil }

// Keep journal errors useful without ever including ticket contents.
func ticketStoreError(err error) error {
	return fmt.Errorf("single-use ticket journal unavailable: %w", err)
}

// A rejection retry must not reuse a consumed PSK, but must still negotiate and
// save a replacement ticket after its new full application authentication.
type freshSessionCache struct{ destination tls.ClientSessionCache }

func (freshSessionCache) Get(string) (*tls.ClientSessionState, bool) { return nil, false }
func (c freshSessionCache) Put(key string, state *tls.ClientSessionState) {
	c.destination.Put(key, state)
}
