/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/peer"
)

/*
C-02: a previously validated peer must never silently return to plaintext.

The attack needs no cryptography and no privileged position on the authority. A
domain has been encrypting for months; its cached manifest eventually expires; an
attacker who can disrupt DNS or the HTTPS path — for as long as one refresh takes
— makes the resolution fail. Before the latch, every automatically discovered
peer then fell through to cleartext, with no error, no bounce and nothing in any
log saying the mail had lost its protection.

01-PRD FR-7 and 04-SECURITY §7 forbid it. This file is the enforcement.
*/

// flakyResolver answers once and then fails, which is the attack in miniature.
type flakyResolver struct {
	res   mailkey.Result
	calls int
	fail  bool
}

func (f *flakyResolver) Resolve(_ context.Context, domain string) (mailkey.Result, error) {
	f.calls++
	if f.fail {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailureNetwork, domain, errors.New("authority unreachable"))
	}
	return f.res, nil
}

// clock is advanceable, because the attack IS the passage of time: the cached
// manifest has to lapse before a disrupted refresh can matter.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func capEnv(t *testing.T, expires time.Time) (*peer.Service, *peer.MemStore, *flakyResolver, *clock) {
	t.Helper()
	now := time.Unix(1750000000, 0).UTC()
	clk := &clock{t: now}
	store := peer.NewMemStore(clk.now)
	// A REAL manifest: the cache path re-parses the stored canonical bytes, so a
	// stand-in would exercise the corrupt-cache branch instead of the one under
	// test.
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	m, err := manifest.New("example.com", now, expires, mailkey.AlgX25519, mailkey.EncAES256GCM, pk)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	r := &flakyResolver{res: mailkey.Result{
		Manifest:   m,
		ManifestID: manifest.ManifestIDOf(raw),
		Raw:        raw,
		FetchedAt:  now,
		ExpiresAt:  expires,
	}}
	svc := peer.NewService(r, store, peer.Options{Now: clk.now})
	t.Cleanup(svc.Close)
	return svc, store, r, clk
}

func TestValidatedPeerNeverDowngradesToPlaintext(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1750000000, 0).UTC()
	svc, store, r, clk := capEnv(t, now.Add(time.Hour))

	// One successful resolution — an ordinary automatically discovered peer,
	// with NO administrator policy configured. This is the case that used to be
	// unprotected, and it is the overwhelming majority of peers.
	if _, err := svc.ResolveForEncryption(ctx, "example.com"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	cap, err := store.Capability(ctx, "example.com")
	if err != nil || !cap.EverValidated || !cap.Requires() {
		t.Fatalf("a successful fetch must latch the capability: %+v (%v)", cap, err)
	}

	// Now the attack: the manifest lapses, and the refresh that would replace it
	// is disrupted for as long as it takes.
	clk.t = now.Add(2 * time.Hour)
	r.fail = true
	_, err = svc.ResolveForEncryption(ctx, "example.com")

	// The demand is precise: it must be ErrEncryptionRequired — a HOLD — not a
	// bare resolution error, which the outbound adapter maps to "no key" and
	// therefore to cleartext.
	if !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("a validated peer with no usable key returned %v — the caller would send this in the clear", err)
	}
}

// TestUnknownDomainStillFallsBack: the latch must not turn every unreachable
// domain into held mail. A domain never validated has no protection to lose, and
// refusing it would make MKDP1 an outage amplifier for the entire internet.
func TestUnknownDomainStillFallsBack(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1750000000, 0).UTC()
	svc, _, r, _ := capEnv(t, now.Add(time.Hour))
	r.fail = true

	_, err := svc.ResolveForEncryption(ctx, "never-seen.test")
	if err == nil {
		t.Fatal("an unreachable unknown domain must still report failure")
	}
	if errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatal("a domain never validated must not be held — it has no protection to lose")
	}
}

/*
TestForgetPreservesTheLatch is the operator-error defense.

"Forget this peer" is cache hygiene: drop what was cached, let the domain be
rediscovered. If it also cleared the latch, the safest-looking button on the
Peers page would be a downgrade — and the next failed refresh would send
plaintext to a domain that had been encrypting for months, because somebody
tidied up.
*/
func TestForgetPreservesTheLatch(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1750000000, 0).UTC()
	svc, store, r, clk := capEnv(t, now.Add(time.Hour))

	if _, err := svc.ResolveForEncryption(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Forget(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if cap, _ := store.Capability(ctx, "example.com"); !cap.Requires() {
		t.Fatal("Forget cleared the downgrade latch")
	}
	// And the protection is still in force, not merely still recorded.
	clk.t = now.Add(2 * time.Hour)
	r.fail = true
	if _, err := svc.ResolveForEncryption(ctx, "example.com"); !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("after Forget the peer downgraded: %v", err)
	}
}

/*
TestOnlyTheAdministratorLiftsTheLatch: exactly one operation re-permits
plaintext, and a later successful fetch does not undo that decision.

The second half matters. If MarkValidated silently re-enabled the requirement,
an administrator's deliberate downgrade would last only until the domain next
answered — which is precisely when they would stop watching.
*/
func TestOnlyTheAdministratorLiftsTheLatch(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1750000000, 0).UTC()
	svc, store, r, clk := capEnv(t, now.Add(time.Hour))

	if _, err := svc.ResolveForEncryption(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetMKDP1Disabled(ctx, "example.com", true, "peer cannot fix their authority", now); err != nil {
		t.Fatal(err)
	}
	clk.t = now.Add(2 * time.Hour)
	r.fail = true
	_, err := svc.ResolveForEncryption(ctx, "example.com")
	if errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatal("an explicit administrator downgrade did not take effect")
	}

	// A later success must not quietly re-arm it.
	clk.t = now
	r.fail = false
	if _, err := svc.ResolveForEncryption(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	cap, _ := store.Capability(ctx, "example.com")
	if !cap.Disabled || cap.Requires() {
		t.Fatalf("a successful fetch reversed the administrator's decision: %+v", cap)
	}
	if cap.Reason == "" {
		t.Fatal("the downgrade must keep its reason for review")
	}

	// Re-enabling restores the protection.
	if err := store.SetMKDP1Disabled(ctx, "example.com", false, "", now); err != nil {
		t.Fatal(err)
	}
	clk.t = now.Add(2 * time.Hour)
	r.fail = true
	if _, err := svc.ResolveForEncryption(ctx, "example.com"); !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("re-enabling did not restore the requirement: %v", err)
	}
}

// TestUnreadableLatchFailsClosed: if the store cannot answer, we must assume the
// domain is protected. Treating a storage blip as "never validated" would make an
// outage indistinguishable from a domain that does not speak MKDP1 — the exact
// substitution the latch exists to prevent.
func TestUnreadableLatchFailsClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1750000000, 0).UTC()
	_, _, r, _ := capEnv(t, now.Add(time.Hour))
	r.fail = true

	svc := peer.NewService(r, brokenCapStore{peer.NewMemStore(func() time.Time { return now })},
		peer.Options{Now: func() time.Time { return now }})
	defer svc.Close()

	if _, err := svc.ResolveForEncryption(ctx, "example.com"); !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("an unreadable latch must fail closed, got %v", err)
	}
}

type brokenCapStore struct{ mailkey.Store }

func (brokenCapStore) Capability(context.Context, string) (mailkey.Capability, error) {
	return mailkey.Capability{}, errors.New("store unavailable")
}
