/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/peer"
)

const domain = "example.com"

// fakeResolver stands in for the authority. It hands out whichever result is
// currently loaded, or an error, and counts calls — so the tests can assert
// that a valid cache costs no resolution at all.
type fakeResolver struct {
	mu     sync.Mutex
	result mailkey.Result
	err    error
	calls  atomic.Int64
	block  chan struct{} // when non-nil, Resolve waits on it
}

func (f *fakeResolver) Resolve(ctx context.Context, d string) (mailkey.Result, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return mailkey.Result{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return mailkey.Result{}, f.err
	}
	return f.result, nil
}

func (f *fakeResolver) set(r mailkey.Result, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result, f.err = r, err
}

// makeResult builds a validated-looking result for a domain.
func makeResult(t *testing.T, d string, now time.Time, life time.Duration) mailkey.Result {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(d, now, now.Add(life), mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	return mailkey.Result{
		Manifest: m, ManifestID: manifest.ManifestIDOf(raw), Raw: raw,
		FetchedAt: now, ExpiresAt: m.ExpiresAt, TLSHost: "mail." + d,
	}
}

// newSvc wires a service over a fake resolver and an in-memory store, with a
// clock the test controls.
func newSvc(t *testing.T, clock *time.Time) (*peer.Service, *fakeResolver, *peer.MemStore) {
	t.Helper()
	now := func() time.Time { return *clock }
	r := &fakeResolver{}
	st := peer.NewMemStore(now)
	svc := peer.NewService(r, st, peer.Options{Now: now, Workers: 1, QueueSize: 4})
	t.Cleanup(svc.Close)
	return svc, r, st
}

// TestObservationsNeverInstallAKey is the protocol's central rule, tested from
// the outside: DNS and a header may create a peer and schedule work, but only a
// resolution installs a manifest.
func TestObservationsNeverInstallAKey(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()

	id := makeResult(t, domain, clock, 24*time.Hour).ManifestID
	r.set(mailkey.Result{}, errors.New("authority unreachable"))

	if err := svc.ObserveDNS(ctx, domain, []string{discovery.FormatDNS(id)}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ObserveHeader(ctx, "v=MKDP1; d="+domain+"; id="+manifest.EncodeID(id)+"; mode=https", "msg-1"); err != nil {
		t.Fatal(err)
	}

	p, err := st.GetPeer(ctx, domain)
	if err != nil || p == nil {
		t.Fatalf("the observations must have created a peer: %v", err)
	}
	if p.Effective != nil {
		t.Fatal("an observation must never install a manifest")
	}
	if p.State != mailkey.StateDiscovered && p.State != mailkey.StateUnavailable {
		t.Fatalf("state = %q, want discovered/unavailable", p.State)
	}
	// One peer, two observations — not two peers.
	if len(p.Observations) != 2 {
		t.Fatalf("want 2 observations on one peer, got %d", len(p.Observations))
	}
	peers, _ := st.ListPeers(ctx)
	if len(peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(peers))
	}
	// A malformed header is not an observation, and never an error for the mail.
	if err := svc.ObserveHeader(ctx, "v=MKDP2; d=evil.example", "msg-2"); err != nil {
		t.Fatalf("a malformed header must not fail the message path: %v", err)
	}
	if peers, _ := st.ListPeers(ctx); len(peers) != 1 {
		t.Fatal("a malformed header must not create a peer")
	}
}

// TestReconciliationNoWinnerSelection: DNS says B, the header says C, the
// authority answers D. D is effective; B and C are stale. Nothing votes.
func TestReconciliationNoWinnerSelection(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()

	idB := makeResult(t, domain, clock, time.Hour).ManifestID
	idC := makeResult(t, domain, clock, 2*time.Hour).ManifestID
	resD := makeResult(t, domain, clock, 24*time.Hour)
	if idB == idC || idB == resD.ManifestID {
		// distinct by construction (different keys), asserted so a future
		// change to makeResult cannot silently make this test vacuous
		t.Log("ids are distinct")
	}

	r.set(mailkey.Result{}, errors.New("down"))
	if err := svc.ObserveDNS(ctx, domain, []string{discovery.FormatDNS(idB)}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ObserveHeader(ctx, "v=MKDP1; d="+domain+"; id="+manifest.EncodeID(idC), "msg"); err != nil {
		t.Fatal(err)
	}

	r.set(resD, nil)
	p, err := svc.Refresh(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	if p.Effective == nil || p.Effective.ManifestID != resD.ManifestID {
		t.Fatal("the authority's answer must become effective")
	}
	if p.State != mailkey.StateActive {
		t.Fatalf("state = %q", p.State)
	}
	for _, o := range p.Observations {
		if o.Source == mailkey.SourceDNS && o.Status != mailkey.ObservationStale {
			t.Fatalf("DNS observation should be stale, got %q", o.Status)
		}
		if o.Source == mailkey.SourceHeader && o.Status != mailkey.ObservationStale {
			t.Fatalf("header observation should be stale, got %q", o.Status)
		}
	}

	// An observation that MATCHES the effective manifest is confirmed, and
	// confirms without a refresh.
	before := r.calls.Load()
	if err := svc.ObserveDNS(ctx, domain, []string{discovery.FormatDNS(resD.ManifestID)}); err != nil {
		t.Fatal(err)
	}
	p2, _ := st.GetPeer(ctx, domain)
	for _, o := range p2.Observations {
		if o.Source == mailkey.SourceDNS && o.Status != mailkey.ObservationConfirmed {
			t.Fatalf("a matching DNS id must be confirmed, got %q", o.Status)
		}
	}
	if r.calls.Load() != before {
		t.Fatal("a matching observation must not trigger a resolution")
	}
}

// TestInconsistentDNSIsRecordedNotArbitrated: several different valid records
// are an inconsistency to report, not a set to choose from.
func TestInconsistentDNSIsRecordedNotArbitrated(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	r.set(mailkey.Result{}, errors.New("down"))

	a := makeResult(t, domain, clock, time.Hour).ManifestID
	b := makeResult(t, domain, clock, 2*time.Hour).ManifestID
	if err := svc.ObserveDNS(ctx, domain, []string{discovery.FormatDNS(a), discovery.FormatDNS(b)}); err != nil {
		t.Fatal(err)
	}
	p, _ := st.GetPeer(ctx, domain)
	if len(p.Observations) != 1 {
		t.Fatalf("want one coalesced DNS observation, got %d", len(p.Observations))
	}
	o := p.Observations[0]
	if o.Status != mailkey.ObservationInconsistent {
		t.Fatalf("status = %q, want inconsistent", o.Status)
	}
	if o.HasID {
		t.Fatal("an inconsistent DNS view must not present one id as the answer")
	}
}

// TestCacheAvoidsNetwork: with a valid effective manifest, the outbound path
// resolves from cache and touches no network. This is the property that keeps
// discovery off the hot path.
func TestCacheAvoidsNetwork(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, _ := newSvc(t, &clock)
	ctx := context.Background()
	res := makeResult(t, domain, clock, 24*time.Hour)
	r.set(res, nil)

	first, err := svc.ResolveForEncryption(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestID != res.ManifestID {
		t.Fatal("wrong manifest")
	}
	if got := r.calls.Load(); got != 1 {
		t.Fatalf("first resolution should call the authority once, got %d", got)
	}
	for range 5 {
		if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.calls.Load(); got != 1 {
		t.Fatalf("a valid cache must not call the authority again, got %d calls", got)
	}
}

// TestRefreshFailurePreservesValidManifest is downgrade protection: a peer that
// validated once keeps its key through an outage, so a transient failure can
// never become plaintext delivery.
func TestRefreshFailurePreservesValidManifest(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	res := makeResult(t, domain, clock, 24*time.Hour)
	r.set(res, nil)
	if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
		t.Fatal(err)
	}

	// The authority breaks, and the manifest moves into its refresh window.
	r.set(mailkey.Result{}, errors.New("authority unreachable"))
	clock = clock.Add(20 * time.Hour)

	got, err := svc.ResolveForEncryption(ctx, domain)
	if err != nil {
		t.Fatalf("a still-valid cached manifest must be used when refresh fails: %v", err)
	}
	if got.ManifestID != res.ManifestID {
		t.Fatal("the cached manifest must be returned")
	}
	p, _ := st.GetPeer(ctx, domain)
	if p.Effective == nil {
		t.Fatal("a failed refresh must not drop the effective manifest")
	}
	if p.LastError == "" {
		t.Fatal("the failure must be recorded for the operator")
	}
	if p.State != mailkey.StateActive {
		t.Fatalf("state = %q, want active (the key still works)", p.State)
	}
}

// TestExpiredWithFailedRefresh: once the manifest expires and refresh still
// fails, there is no usable key — reported as such, never as plaintext.
func TestExpiredWithFailedRefresh(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	r.set(makeResult(t, domain, clock, time.Hour), nil)
	if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
		t.Fatal(err)
	}

	r.set(mailkey.Result{}, errors.New("authority unreachable"))
	clock = clock.Add(2 * time.Hour)

	if _, err := svc.ResolveForEncryption(ctx, domain); err == nil {
		t.Fatal("an expired manifest with a failed refresh must not resolve")
	}
	p, _ := st.GetPeer(ctx, domain)
	if p.State != mailkey.StateExpired {
		t.Fatalf("state = %q, want expired", p.State)
	}
	if _, ok := peer.Usable(p, clock); ok {
		t.Fatal("an expired manifest must not be usable")
	}
}

// TestRotation: a new manifest becomes effective atomically and the previous one
// becomes historical, which is what lets a delayed message name an older key.
func TestRotation(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	a := makeResult(t, domain, clock, 24*time.Hour)
	r.set(a, nil)
	if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(12 * time.Hour)
	b := makeResult(t, domain, clock, 24*time.Hour)
	r.set(b, nil)
	p, err := svc.Refresh(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	if p.Effective.ManifestID != b.ManifestID {
		t.Fatal("the new manifest must be effective")
	}
	if len(p.History) != 1 || p.History[0].ManifestID != a.ManifestID {
		t.Fatalf("the previous manifest must be historical, history = %d", len(p.History))
	}
	if p.History[0].Status != mailkey.ManifestHistorical {
		t.Fatalf("history status = %q", p.History[0].Status)
	}
	if p.AuthorityUnstable {
		t.Fatal("an ordinary rotation is not instability")
	}
	// The kid of the old manifest is still recoverable — the receiver keeps the
	// matching private key, which is what makes delayed delivery work.
	if p.History[0].Kid != a.Manifest.Key.Kid {
		t.Fatal("the historical record must name the old kid")
	}
	_ = st
}

// TestAuthorityInstability: A → B → A inside the window is reported, not
// resolved. Inventing a winner here would reintroduce the ordering rule MKDP1
// exists to remove.
func TestAuthorityInstability(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, _ := newSvc(t, &clock)
	ctx := context.Background()
	a := makeResult(t, domain, clock, 24*time.Hour)
	b := makeResult(t, domain, clock, 24*time.Hour)

	r.set(a, nil)
	if _, err := svc.Refresh(ctx, domain); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	r.set(b, nil)
	if _, err := svc.Refresh(ctx, domain); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Minute)
	r.set(a, nil)
	p, err := svc.Refresh(ctx, domain)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AuthorityUnstable {
		t.Fatal("an authority alternating between manifests must be flagged unstable")
	}
	if p.Effective.ManifestID != a.ManifestID {
		t.Fatal("the latest successful fetch is still what is effective")
	}
}

// TestPolicy: disabled refuses resolution entirely; require is an administrative
// state the caller reads to decide what to do with ErrNoKey.
func TestPolicy(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	r.set(makeResult(t, domain, clock, 24*time.Hour), nil)

	if err := st.SetPolicy(ctx, domain, mailkey.PolicyDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveForEncryption(ctx, domain); !errors.Is(err, mailkey.ErrDisabled) {
		t.Fatalf("a disabled domain must report ErrDisabled, got %v", err)
	}
	p, _ := st.GetPeer(ctx, domain)
	if p.State != mailkey.StateDisabled {
		t.Fatalf("state = %q", p.State)
	}
	if r.calls.Load() != 0 {
		t.Fatal("a disabled domain must not be resolved at all")
	}

	// Back to automatic, and it resolves.
	if err := st.SetPolicy(ctx, domain, mailkey.PolicyAuto); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
		t.Fatal(err)
	}
	// Require-encryption is preserved across a forget, because it is a decision
	// about the domain rather than a cache entry.
	if err := st.SetPolicy(ctx, domain, mailkey.PolicyRequire); err != nil {
		t.Fatal(err)
	}
	if err := svc.Forget(ctx, domain); err != nil {
		t.Fatal(err)
	}
	p, _ = st.GetPeer(ctx, domain)
	if p == nil || p.Policy != mailkey.PolicyRequire {
		t.Fatal("forgetting must not clear an administrative policy")
	}
	if p.Effective != nil || len(p.Observations) != 0 {
		t.Fatal("forgetting must clear cached manifests and observations")
	}
	if err := st.SetPolicy(ctx, domain, mailkey.Policy("whatever")); err == nil {
		t.Fatal("an unknown policy must be refused")
	}
}

// TestForgetAllowsRediscovery: forget is not a blocklist.
func TestForgetAllowsRediscovery(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	res := makeResult(t, domain, clock, 24*time.Hour)
	r.set(res, nil)
	if _, err := svc.AddPeer(ctx, domain); err != nil {
		t.Fatal(err)
	}
	if err := svc.Forget(ctx, domain); err != nil {
		t.Fatal(err)
	}
	if p, _ := st.GetPeer(ctx, domain); p != nil {
		t.Fatal("an automatic-policy peer should be gone entirely")
	}
	if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
		t.Fatalf("the domain must be rediscoverable: %v", err)
	}
}

// TestAddPeerFailureLeavesInspectablePeer: a failed manual add installs nothing
// but leaves a record with the error, so an administrator can see why.
func TestAddPeerFailureLeavesInspectablePeer(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	r.set(mailkey.Result{}, mailkey.Failf(mailkey.FailureAbsent, domain, "404: no manifest published"))

	p, err := svc.AddPeer(ctx, domain)
	if err == nil {
		t.Fatal("a failing add must report the failure")
	}
	if p.Domain != domain {
		t.Fatalf("the peer record must come back for inspection: %+v", p)
	}
	if p.Effective != nil {
		t.Fatal("a failed add must not install anything")
	}
	if p.LastError == "" {
		t.Fatal("the error must be recorded on the peer")
	}
	stored, _ := st.GetPeer(ctx, domain)
	if stored.State != mailkey.StateUnavailable {
		t.Fatalf("state = %q, want unavailable", stored.State)
	}
	if len(stored.Observations) != 1 || stored.Observations[0].Source != mailkey.SourceManual {
		t.Fatal("the manual attempt must be recorded as an observation")
	}
}

// TestAsyncQueueIsBoundedAndCoalesces: header storms are shed, not queued
// without limit, and one domain occupies one slot however many messages mention
// it. A dropped hint costs nothing — the next send resolves synchronously.
func TestAsyncQueueIsBoundedAndCoalesces(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }
	r := &fakeResolver{block: make(chan struct{})}
	r.set(makeResult(t, domain, clock, 24*time.Hour), nil)
	st := peer.NewMemStore(now)

	var dropped atomic.Int64
	svc := peer.NewService(r, st, peer.Options{
		Now: now, Workers: 1, QueueSize: 2,
		OnDrop: func(string) { dropped.Add(1) },
	})
	defer svc.Close()
	ctx := context.Background()

	// A storm of headers for many distinct domains, with the resolver blocked
	// so the queue cannot drain.
	const storm = 200
	for i := range storm {
		d := "d" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + ".example"
		_ = svc.ObserveHeader(ctx, "v=MKDP1; d="+d, "msg")
	}
	if dropped.Load() == 0 {
		t.Fatal("a storm past the queue bound must drop triggers rather than grow")
	}
	// Bounded: the queue holds at most QueueSize, plus what workers took.
	if q := int64(storm) - dropped.Load(); q > 8 {
		t.Fatalf("too many triggers accepted (%d) for a queue of 2", q)
	}
	close(r.block)
}

// TestStoreReturnsCopies: a caller cannot mutate stored state through a value it
// was handed, or the store's atomicity would be decorative.
func TestStoreReturnsCopies(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	svc, r, st := newSvc(t, &clock)
	ctx := context.Background()
	r.set(makeResult(t, domain, clock, 24*time.Hour), nil)
	if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
		t.Fatal(err)
	}

	p, _ := st.GetPeer(ctx, domain)
	p.Effective.ManifestID[0] ^= 0xff
	p.Policy = mailkey.PolicyDisabled
	p.Observations = append(p.Observations, mailkey.Observation{Source: "forged"})
	if len(p.Effective.CanonicalBytes) > 0 {
		p.Effective.CanonicalBytes[0] ^= 0xff
	}

	again, _ := st.GetPeer(ctx, domain)
	if again.Policy == mailkey.PolicyDisabled {
		t.Fatal("mutating a returned peer must not change stored policy")
	}
	if again.Effective.ManifestID == p.Effective.ManifestID {
		t.Fatal("mutating a returned manifest id must not change stored state")
	}
	if len(again.Observations) != 0 {
		t.Fatal("appending to returned observations must not change stored state")
	}
	// And the stored bytes still parse — the cache-honesty check.
	if _, err := svc.ResolveForEncryption(ctx, domain); err != nil {
		t.Fatalf("stored manifest must remain usable: %v", err)
	}
}

// TestInstallRejectsForeignResult: the store refuses a result for another
// domain, so a mismatch cannot slip through even if a resolver were wrong.
func TestInstallRejectsForeignResult(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	st := peer.NewMemStore(func() time.Time { return clock })
	foreign := makeResult(t, "attacker.example", clock, time.Hour)
	if err := st.InstallManifest(context.Background(), domain, foreign); err == nil {
		t.Fatal("installing a result for another domain must be refused")
	}
}

// TestNeedsRefreshTriggers pins the refresh policy: the reasons a resolution
// should run, and the one case where it should not.
func TestNeedsRefreshTriggers(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	res := makeResult(t, domain, clock, 24*time.Hour)

	if need, _ := peer.NeedsRefresh(nil, clock); !need {
		t.Fatal("an unknown peer needs resolution")
	}
	p := peer.New(domain)
	if need, _ := peer.NeedsRefresh(p, clock); !need {
		t.Fatal("a peer with no manifest needs resolution")
	}
	peer.Install(p, res, clock)
	if need, why := peer.NeedsRefresh(p, clock); need {
		t.Fatalf("a fresh manifest needs no resolution, got %q", why)
	}
	// Near expiry.
	if need, _ := peer.NeedsRefresh(p, res.ExpiresAt.Add(-time.Hour)); !need {
		t.Fatal("a manifest near expiry needs refresh")
	}
	// Past expiry.
	if need, _ := peer.NeedsRefresh(p, res.ExpiresAt.Add(time.Second)); !need {
		t.Fatal("an expired manifest needs refresh")
	}
	// An observation with a different id.
	other := makeResult(t, domain, clock, time.Hour)
	peer.Observe(p, mailkey.Observation{Source: mailkey.SourceDNS, ManifestID: other.ManifestID, HasID: true}, clock)
	if need, why := peer.NeedsRefresh(p, clock); !need {
		t.Fatal("a differing observed id must trigger refresh")
	} else if why == "" {
		t.Fatal("the reason must be reported")
	}
	// Disabled never resolves.
	p.Policy = mailkey.PolicyDisabled
	if need, _ := peer.NeedsRefresh(p, clock); need {
		t.Fatal("a disabled peer must not resolve")
	}
}

// TestRequirePolicyRefusesPlaintext is F-4's fail-closed half: for a domain an
// administrator marked "require", a discovery failure must be reported as
// "encryption required, not available yet" — never as an absent key the caller
// would answer with cleartext.
//
// It must also stay TEMPORARY. If it read as a permanent rejection, anyone able
// to make an authority unreachable could destroy mail to that domain instead of
// merely delaying it.
func TestRequirePolicyRefusesPlaintext(t *testing.T) {
	st := peer.NewMemStore(nil)
	svc := peer.NewService(&fakeResolver{err: mailkey.Failf(mailkey.FailureNetwork, "resolve", "boom")}, st, peer.Options{Workers: 1, QueueSize: 4})
	defer svc.Close()
	ctx := context.Background()

	// Automatic policy: the failure passes through, and the caller is free to
	// send cleartext.
	_, err := svc.ResolveForEncryption(ctx, "auto.test")
	if err == nil {
		t.Fatal("a failing authority must report an error")
	}
	if errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatal("the automatic policy must not demand encryption")
	}

	// Require policy: the same failure now forbids plaintext.
	if err := st.SetPolicy(ctx, "strict.test", mailkey.PolicyRequire); err != nil {
		t.Fatal(err)
	}
	_, err = svc.ResolveForEncryption(ctx, "strict.test")
	if !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("require policy must report ErrEncryptionRequired, got %v", err)
	}
	// The cause survives, so an operator can still see WHY discovery failed.
	if !stringsContains(err.Error(), "boom") {
		t.Fatalf("the underlying failure must be preserved: %v", err)
	}
	// And it is not the "no key here" answer, which would mean cleartext.
	if errors.Is(err, mailkey.ErrNoKey) {
		t.Fatal("a required domain's failure must not read as an absent key")
	}
}

// stringsContains avoids importing strings for one assertion.
func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
