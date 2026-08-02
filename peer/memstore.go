/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"golang.org/x/xerrors"
)

// MemStore is an in-memory mailkey.Store: the reference implementation of the
// persistence contract, and enough for tests and small single-node deployments.
// A durable host application (Mailnite's badger store) implements the same
// interface and calls the same state functions, so the two cannot drift on
// semantics — only on where the bytes live.
//
// Atomicity here is a mutex. A database-backed store owes the same guarantee
// through whatever transaction it has: InstallManifest must never be observable
// halfway, or a client could see a peer naming a manifest that is not stored.
type MemStore struct {
	mu    sync.Mutex
	peers map[string]*mailkey.Peer
	// caps is kept in its OWN map, not as a field of Peer, so that deleting a
	// peer cannot delete the latch by accident. The separation is the guarantee:
	// ForgetPeer touches peers and nothing else, and no future edit to the peer
	// record can quietly take the downgrade protection with it.
	caps map[string]mailkey.Capability
	now  func() time.Time
}

var _ mailkey.Store = (*MemStore)(nil)

// NewMemStore builds an empty store. now may be nil (time.Now).
func NewMemStore(now func() time.Time) *MemStore {
	if now == nil {
		now = time.Now
	}
	return &MemStore{peers: map[string]*mailkey.Peer{}, now: now}
}

// GetPeer returns a COPY: callers must not be able to mutate stored state
// without going through the store, or the atomicity guarantee is decorative.
func (s *MemStore) GetPeer(_ context.Context, domain string) (*mailkey.Peer, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[d]
	if !ok {
		return nil, nil
	}
	cp := clonePeer(p)
	Reconcile(cp, s.now()) // state is derived, so it is current when read
	return cp, nil
}

func (s *MemStore) ListPeers(_ context.Context) ([]mailkey.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]mailkey.Peer, 0, len(s.peers))
	for _, p := range s.peers {
		cp := clonePeer(p)
		Reconcile(cp, now)
		out = append(out, *cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}

func (s *MemStore) PutObservation(_ context.Context, domain string, o mailkey.Observation) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.upsertLocked(d)
	Observe(p, o, s.now())
	return nil
}

func (s *MemStore) InstallManifest(_ context.Context, domain string, r mailkey.Result) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	if r.Manifest.Domain != d {
		// A result for another domain must never land on this peer — the
		// resolver already pins this, and the store refuses to be the place
		// where a mismatch slips through.
		return xerrors.Errorf("install: result describes %q, peer is %q", r.Manifest.Domain, d)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.upsertLocked(d)
	if p.Policy == mailkey.PolicyDisabled {
		return mailkey.ErrDisabled
	}
	Install(p, r, s.now())
	return nil
}

func (s *MemStore) RecordFailure(_ context.Context, domain string, ferr error) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.upsertLocked(d)
	Fail(p, ferr, s.now())
	return nil
}

// RecordIssue folds one occurrence under the lock, so "was this the first?" is
// decided by the same critical section that writes it. Two concurrent sends to
// a newly broken domain must not both conclude they were first and both alert.
func (s *MemStore) RecordIssue(_ context.Context, domain string, code mailkey.IssueCode, detail string) (bool, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.upsertLocked(d)
	issues, first := mailkey.CoalesceIssue(p.Issues, code, detail, s.now())
	p.Issues = issues
	return first, nil
}

func (s *MemStore) ClearIssue(_ context.Context, domain string, code mailkey.IssueCode) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.upsertLocked(d)
	p.Issues = mailkey.ClearIssue(p.Issues, code)
	return nil
}

func (s *MemStore) SetPolicy(_ context.Context, domain string, policy mailkey.Policy) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	switch policy {
	case mailkey.PolicyAuto, mailkey.PolicyRequire, mailkey.PolicyDisabled:
	default:
		return xerrors.Errorf("unknown policy %q", policy)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.upsertLocked(d)
	p.Policy = policy
	Reconcile(p, s.now())
	return nil
}

func (s *MemStore) ForgetPeer(_ context.Context, domain string) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[d]
	if !ok {
		return nil
	}
	// An administrative policy survives forgetting: "disabled" is a decision
	// about the domain, not a cache entry. Everything else goes.
	if p.Policy == mailkey.PolicyAuto {
		delete(s.peers, d)
		return nil
	}
	Forget(p)
	return nil
}

func (s *MemStore) upsertLocked(d string) *mailkey.Peer {
	p, ok := s.peers[d]
	if !ok {
		p = New(d)
		s.peers[d] = p
	}
	return p
}

// clonePeer deep-copies the mutable parts so a caller cannot reach into stored
// state through a slice or pointer it was handed.
func clonePeer(p *mailkey.Peer) *mailkey.Peer {
	cp := *p
	if p.Effective != nil {
		rec := *p.Effective
		rec.CanonicalBytes = append([]byte(nil), p.Effective.CanonicalBytes...)
		cp.Effective = &rec
	}
	if len(p.History) > 0 {
		cp.History = make([]mailkey.ManifestRecord, len(p.History))
		for i, h := range p.History {
			h.CanonicalBytes = append([]byte(nil), h.CanonicalBytes...)
			cp.History[i] = h
		}
	}
	if len(p.Observations) > 0 {
		cp.Observations = append([]mailkey.Observation(nil), p.Observations...)
	}
	return &cp
}

// --- capability latch ---------------------------------------------------------

func (s *MemStore) Capability(_ context.Context, domain string) (mailkey.Capability, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return mailkey.Capability{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.caps[d], nil
}

func (s *MemStore) MarkValidated(_ context.Context, domain string, at time.Time) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caps == nil {
		s.caps = map[string]mailkey.Capability{}
	}
	c := s.caps[d]
	if !c.EverValidated {
		c.EverValidated, c.FirstValidatedAt = true, at
	}
	c.LastValidatedAt = at
	// A successful fetch does NOT lift an administrator's downgrade. The latch
	// records capability; Disabled records a decision, and only the operator who
	// made it may reverse it.
	s.caps[d] = c
	return nil
}

func (s *MemStore) SetMKDP1Disabled(_ context.Context, domain string, disabled bool, reason string, at time.Time) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caps == nil {
		s.caps = map[string]mailkey.Capability{}
	}
	c := s.caps[d]
	c.Disabled, c.DisabledAt, c.Reason = disabled, at, reason
	if !disabled {
		c.DisabledAt, c.Reason = time.Time{}, ""
	}
	s.caps[d] = c
	return nil
}

// PutPeerForTest replaces a peer record wholesale. It exists so a test can put
// the store into a state the protocol paths cannot produce — a truncated
// manifest, a partial write, a restored backup — because those are exactly the
// states an attacker arranges and they must not end in plaintext.
func (s *MemStore) PutPeerForTest(_ context.Context, p *mailkey.Peer) error {
	d, err := discovery.Normalize(p.Domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[d] = clonePeer(p)
	return nil
}

// SetIdentity persists the pin and its observations. It creates a record for a
// domain not yet known: a trust decision may be reached on the first fetch,
// before any observation made the peer durable.
func (s *MemStore) SetIdentity(_ context.Context, domain string, st mailkey.IdentityState) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.peers[d]
	if !ok {
		p = &mailkey.Peer{Domain: d, State: mailkey.StateDiscovered}
		s.peers[d] = p
	}
	p.Identity = st
	return nil
}

// ListCapabilities returns every latched domain. Copies out, like every other
// read: a caller holding a map into the store could otherwise clear a latch by
// mutating what it was shown.
func (s *MemStore) ListCapabilities(context.Context) (map[string]mailkey.Capability, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]mailkey.Capability, len(s.caps))
	for d, c := range s.caps {
		out[d] = c
	}
	return out, nil
}
