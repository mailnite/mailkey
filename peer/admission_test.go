/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/peer"
)

/*
Admission control: what a stranger's header may cost us.

The queue bound was always tested (a storm drops triggers rather than growing).
What these tests pin is the other half — that a storm cannot WRITE without
limit either, which is the part that survives a restart.
*/

// countingStore delegates to a MemStore and counts the writes, because the
// property under test is exactly "how many times did storage get touched".
type countingStore struct {
	*peer.MemStore
	writes atomic.Int64
}

func (c *countingStore) PutObservation(ctx context.Context, domain string, o mailkey.Observation) error {
	c.writes.Add(1)
	return c.MemStore.PutObservation(ctx, domain, o)
}

func newCounting(now func() time.Time) *countingStore {
	return &countingStore{MemStore: peer.NewMemStore(now)}
}

// header renders a Mail-Key value. Every field is required, so a test that
// only needs "this domain was mentioned" still has to name a manifest —
// anyID serves for that.
func header(d string, id mailkey.ManifestID) string {
	h, err := discovery.FormatHeader(d, id)
	if err != nil {
		panic(err)
	}
	return h
}

// anyID is a well-formed manifest id for tests that do not care which one.
func anyID(b byte) mailkey.ManifestID {
	var id mailkey.ManifestID
	for i := range id {
		id[i] = b
	}
	return id
}

// TestRepeatedHeadersCostOneWrite: the ordinary flood. One sender, one domain,
// one id, ten thousand messages — all saying the same thing, so nine thousand
// nine hundred and ninety-nine of them must not reach storage.
func TestRepeatedHeadersCostOneWrite(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }
	st := newCounting(now)
	svc := peer.NewService(&fakeResolver{err: mailkey.Failf(mailkey.FailureNetwork, "resolve", "offline")}, st,
		peer.Options{Now: now, Workers: 1, QueueSize: 4})
	defer svc.Close()
	ctx := context.Background()

	id := makeResult(t, domain, clock, 24*time.Hour).ManifestID
	for range 10_000 {
		if err := svc.ObserveHeader(ctx, header(domain, id), "inbound"); err != nil {
			t.Fatal(err)
		}
	}
	if got := st.writes.Load(); got != 1 {
		t.Fatalf("10000 identical headers wrote %d observations, want 1", got)
	}

	// The interval expiring lets the evidence be recorded again — the point is
	// to coalesce a flood, not to stop listening to the domain.
	clock = clock.Add(11 * time.Minute)
	if err := svc.ObserveHeader(ctx, header(domain, id), "inbound"); err != nil {
		t.Fatal(err)
	}
	if got := st.writes.Load(); got != 2 {
		t.Fatalf("after the interval the observation should be recorded again: %d writes", got)
	}
}

// TestRotationIsNeverRateLimited: a CHANGED id is the one observation that
// matters — it is how a peer learns its cached key is stale. Coalescing it
// would be rate-limiting the protocol itself.
func TestRotationIsNeverRateLimited(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }
	st := newCounting(now)
	svc := peer.NewService(&fakeResolver{err: mailkey.Failf(mailkey.FailureNetwork, "resolve", "offline")}, st,
		peer.Options{Now: now, Workers: 1, QueueSize: 4})
	defer svc.Close()
	ctx := context.Background()

	first := makeResult(t, domain, clock, 24*time.Hour).ManifestID
	second := makeResult(t, domain, clock, 48*time.Hour).ManifestID
	if first == second {
		t.Fatal("test setup: the two manifests must differ")
	}
	for range 100 {
		_ = svc.ObserveHeader(ctx, header(domain, first), "inbound")
	}
	// No clock movement at all: strictly inside the coalescing interval.
	if err := svc.ObserveHeader(ctx, header(domain, second), "inbound"); err != nil {
		t.Fatal(err)
	}
	if got := st.writes.Load(); got != 2 {
		t.Fatalf("a rotation inside the interval must still be recorded: %d writes, want 2", got)
	}
}

// TestUnknownDomainFloodIsQuotad: a million unique domains is a different
// attack from a million messages about one. Every first sighting is genuinely
// new evidence, so coalescing cannot help — the bucket has to.
func TestUnknownDomainFloodIsQuotad(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }
	st := newCounting(now)
	var dropped atomic.Int64
	svc := peer.NewService(&fakeResolver{err: mailkey.Failf(mailkey.FailureNetwork, "resolve", "offline")}, st,
		peer.Options{
			Now: now, Workers: 1, QueueSize: 4,
			NewPeerBurst: 10, NewPeerEvery: time.Minute,
			OnDrop: func(string) { dropped.Add(1) },
		})
	defer svc.Close()
	ctx := context.Background()

	const flood = 500
	for i := range flood {
		_ = svc.ObserveHeader(ctx, header("d"+strconv.Itoa(i)+".example", anyID(1)), "inbound")
	}
	peers, err := st.ListPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) > 10 {
		t.Fatalf("%d unknown domains created %d durable peers, want at most the burst of 10", flood, len(peers))
	}
	if dropped.Load() == 0 {
		t.Fatal("refusals must be visible to the host, not silent")
	}

	// The bucket refills, so discovery resumes — a quota, not a wall.
	clock = clock.Add(5 * time.Minute)
	for i := range 3 {
		_ = svc.ObserveHeader(ctx, header("later"+strconv.Itoa(i)+".example", anyID(1)), "inbound")
	}
	peers, err = st.ListPeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) < 12 {
		t.Fatalf("after refill new domains should be admitted again, have %d peers", len(peers))
	}
}

// TestKnownDomainsDoNotSpendQuota: the bucket is about durable rows, so an
// update to a peer that already exists must not compete with first sightings.
// Otherwise a flood of unknown domains would starve the peers we actually
// correspond with.
func TestKnownDomainsDoNotSpendQuota(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }
	st := newCounting(now)
	svc := peer.NewService(&fakeResolver{err: mailkey.Failf(mailkey.FailureNetwork, "resolve", "offline")}, st,
		peer.Options{
			Now: now, Workers: 1, QueueSize: 4,
			NewPeerBurst: 1, NewPeerEvery: time.Hour,
		})
	defer svc.Close()
	ctx := context.Background()

	// Spend the single token on this domain.
	if err := svc.ObserveHeader(ctx, header(domain, anyID(2)), "inbound"); err != nil {
		t.Fatal(err)
	}
	// A second, unknown domain is refused — the bucket is empty.
	_ = svc.ObserveHeader(ctx, header("stranger.example", anyID(3)), "inbound")

	// But the known domain keeps being heard: a new id, well past the interval.
	clock = clock.Add(11 * time.Minute)
	id := makeResult(t, domain, clock, 24*time.Hour).ManifestID
	if err := svc.ObserveHeader(ctx, header(domain, id), "inbound"); err != nil {
		t.Fatal(err)
	}
	p, err := st.GetPeer(ctx, domain)
	if err != nil || p == nil {
		t.Fatalf("the known peer disappeared: %v", err)
	}
	var seen bool
	for _, o := range p.Observations {
		if o.HasID && o.ManifestID == id {
			seen = true
		}
	}
	if !seen {
		t.Fatal("an empty new-peer bucket must not silence a domain we already know")
	}
	peers, _ := st.ListPeers(ctx)
	if len(peers) != 1 {
		t.Fatalf("the refused stranger should not have been stored: %d peers", len(peers))
	}
}

// TestOperatorOutranksAdmission: a refusal is a cache, and an administrator
// asking for a domain must never be answered from it.
func TestOperatorOutranksAdmission(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }
	st := newCounting(now)
	r := &fakeResolver{}
	r.set(makeResult(t, "wanted.example", clock, 24*time.Hour), nil)
	svc := peer.NewService(r, st, peer.Options{
		Now: now, Workers: 1, QueueSize: 4,
		NewPeerBurst: 1, NewPeerEvery: time.Hour,
	})
	defer svc.Close()
	ctx := context.Background()

	_ = svc.ObserveHeader(ctx, header(domain, anyID(2)), "inbound")           // spends the token
	_ = svc.ObserveHeader(ctx, header("wanted.example", anyID(4)), "inbound") // refused

	p, err := svc.AddPeer(ctx, "wanted.example")
	if err != nil {
		t.Fatalf("an operator's AddPeer must not be refused by admission: %v", err)
	}
	if p.Effective == nil {
		t.Fatal("AddPeer resolved nothing")
	}
}
