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
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/peer"
)

/*
The sender following a rotation, end to end through the resolve path.

Before this, a legitimate rotation and an authority takeover produced the same
outcome — a hold and an alert — which was correct only for the takeover. With
the chain published, "stranger" divides: a signer the history explains is a
successor, followed without a human; one it does not stays a stranger, refused
exactly as before.
*/

// chainResolver serves a fixed manifest plus a fixed identity document — the
// authority as a sender sees it, both endpoints.
type chainResolver struct {
	res      mailkey.Result
	doc      []byte
	docErr   error
	chainHit *int
}

func (c *chainResolver) Resolve(context.Context, string, string) (mailkey.Result, error) {
	return c.res, nil
}

func (c *chainResolver) ResolveIdentityChain(context.Context, string) ([]byte, error) {
	if c.chainHit != nil {
		*c.chainHit++
	}
	return c.doc, c.docErr
}

/*
realResult builds a fetch result whose Raw is a REAL canonical manifest, signed
by the given identity seed.

The cheap fixture (identity_test's result()) carries placeholder bytes, which is
fine for verdict tests and wrong here: followRotation INSTALLS what it accepts,
and the next resolve re-parses the cached bytes — the cache staying honest by
re-parsing is itself a shipped behaviour, so a fixture that cannot survive it
would pass the first resolve and fail the property under test.
*/
func realResult(t *testing.T, dom string, now time.Time, signSeed byte) mailkey.Result {
	t.Helper()
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = signSeed + 100
	}
	m, err := manifest.New(dom, now, now.Add(7*24*time.Hour), mailkey.AlgX25519, mailkey.EncAES256GCM, pk)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	res := mailkey.Result{
		Manifest: m, ManifestID: manifest.ManifestIDOf(raw), Raw: raw,
		FetchedAt: now, ExpiresAt: m.ExpiresAt,
	}
	fp, ipk, priv := fpFor(t, dom, signSeed)
	sig, err := identity.SignManifest(priv, dom, raw)
	if err != nil {
		t.Fatal(err)
	}
	res.Proof = &mailkey.Proof{PublicKey: ipk, Fingerprint: fp, Signature: sig}
	return res
}

// pinnedStore is a MemStore with an established pin INCLUDING the public key —
// the state every pin created since the key rode along has.
func pinnedStore(t *testing.T, dom string, fp mailkey.Fingerprint, pk []byte, now time.Time) *peer.MemStore {
	t.Helper()
	store := peer.NewMemStore(func() time.Time { return now })
	if err := store.SetIdentity(context.Background(), dom, mailkey.IdentityState{
		Status: mailkey.IdentityPinned, Fingerprint: fp, PinnedPublicKey: pk,
		EverHTTPSValidated: true,
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func docFor(t *testing.T, dom string, activeSeed int, chain []identity.Statement, now time.Time) []byte {
	t.Helper()
	fp, pk, _ := fpFor(t, dom, byte(activeSeed))
	raw, err := identity.PackDoc(identity.Doc{
		Domain: dom, ActiveFP: fp, ActivePK: pk,
		Status: identity.StatusActive, UpdatedAt: now, Chain: chain,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestASignedRotationIsFollowedWithoutAHuman(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	fp1, pk1, priv1 := fpFor(t, dom, 1)
	fp2, _, priv2 := fpFor(t, dom, 2)

	stmt, err := identity.SignRotation(dom, priv1, priv2, now, now, now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	r := &chainResolver{
		res:      realResult(t, dom, now, 2), // signed by the NEW identity
		doc:      docFor(t, dom, 2, []identity.Statement{stmt}, now),
		chainHit: &hits,
	}
	store := pinnedStore(t, dom, fp1, []byte(pk1), now)
	oldState, err := store.GetPeer(ctx, dom)
	if err != nil {
		t.Fatal(err)
	}
	oldState.Identity.LastVerifiedIssuedAt = now.Add(time.Hour)
	oldState.Identity.LastVerifiedManifestID = mailkey.ManifestID{7, 7, 7}
	if err := store.SetIdentity(ctx, dom, oldState.Identity); err != nil {
		t.Fatal(err)
	}
	svc := peer.NewService(r, store, peer.Options{Now: func() time.Time { return now }})
	t.Cleanup(svc.Close)

	res, err := svc.ResolveForEncryption(ctx, dom)
	if err != nil {
		t.Fatalf("a published, signed rotation still held the mail: %v", err)
	}
	if res.Proof == nil || res.Proof.Fingerprint != fp2 {
		t.Fatalf("resolved to the wrong identity: %+v", res.Proof)
	}
	p, err := store.GetPeer(ctx, dom)
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity.Fingerprint != fp2 || p.Identity.Status != mailkey.IdentityPinned {
		t.Fatalf("the pin did not move: %+v", p.Identity)
	}
	if len(p.Identity.PinnedPublicKey) == 0 {
		t.Fatal("the new pin lost its public key — the NEXT rotation would be unfollowable")
	}
	if !p.Identity.LastVerifiedIssuedAt.Equal(r.res.Manifest.IssuedAt) ||
		p.Identity.LastVerifiedManifestID != r.res.ManifestID {
		t.Fatalf("the successor identity inherited the predecessor's replay watermark: %+v", p.Identity)
	}
	if hits != 1 {
		t.Fatalf("the chain was fetched %d times; it is consulted only when the signer changes", hits)
	}
	// The NEXT send takes the ordinary pinned path: no chain fetch at all.
	if _, err := svc.ResolveForEncryption(ctx, dom); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("a settled pin re-fetched the chain (%d) — §4.2 forbids per-refresh fetches", hits)
	}
}

// A signer the history does NOT explain stays a stranger: the walk ends
// somewhere else, and the refusal is exactly what it was before chains existed.
func TestAChainThatDoesNotReachTheSignerMovesNothing(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	fp1, pk1, priv1 := fpFor(t, dom, 1)
	_, _, priv3 := fpFor(t, dom, 3)

	// A real rotation — to identity 3. The manifest is signed by identity 2.
	stmt, err := identity.SignRotation(dom, priv1, priv3, now, now, now.Add(time.Hour*24*365))
	if err != nil {
		t.Fatal(err)
	}
	r := &chainResolver{
		res: result(t, dom, now, 2),
		doc: docFor(t, dom, 2, []identity.Statement{stmt}, now),
	}
	store := pinnedStore(t, dom, fp1, []byte(pk1), now)
	svc := peer.NewService(r, store, peer.Options{Now: func() time.Time { return now }})
	t.Cleanup(svc.Close)

	_, err = svc.ResolveForEncryption(ctx, dom)
	if err == nil {
		t.Fatal("a manifest whose signer the history never reaches was accepted")
	}
	if !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("the hold weakened: %v", err)
	}
	p, _ := store.GetPeer(ctx, dom)
	if p.Identity.Fingerprint != fp1 {
		t.Fatal("the pin moved on a chain that explains a different identity")
	}
}

// TestSuccessorOnlyRevocationCannotInstallItsSigner exercises C-05 through the
// complete refresh path. The attacker serves a manifest signed by identity 2
// and a revocation that names the victim's pin as old_fp but is signed only by
// identity 2. The chain must fail before SetIdentity or InstallManifest can
// move durable trust or install the attacker's X25519 key.
func TestSuccessorOnlyRevocationCannotInstallItsSigner(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	fp1, pk1, _ := fpFor(t, dom, 1)
	fp2, pk2, priv2 := fpFor(t, dom, 2)

	forged, err := identity.SignStatement(identity.Statement{
		Type: identity.RevocationType, Version: mailkey.Version, Domain: dom,
		OldFP: fp1, NewFP: fp2, NewAlg: identity.Alg, NewPK: pk2,
		NotBefore: now, CreatedAt: now, ExpiresAt: now.Add(10 * 365 * 24 * time.Hour),
		Reason: "old key unavailable",
	}, nil, priv2)
	if err != nil {
		t.Fatal(err)
	}
	r := &chainResolver{
		res: realResult(t, dom, now, 2),
		doc: docFor(t, dom, 2, []identity.Statement{forged}, now),
	}
	store := pinnedStore(t, dom, fp1, []byte(pk1), now)
	svc := peer.NewService(r, store, peer.Options{Now: func() time.Time { return now }})
	t.Cleanup(svc.Close)

	if _, err := svc.ResolveForEncryption(ctx, dom); !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("successor-only revocation did not hold delivery: %v", err)
	}
	p, err := store.GetPeer(ctx, dom)
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity.Status != mailkey.IdentityPinned || p.Identity.Fingerprint != fp1 {
		t.Fatalf("successor-only revocation moved durable trust: %+v", p.Identity)
	}
	if p.Effective != nil {
		t.Fatal("the attacker's manifest became effective")
	}
}

// A revoked identity holds the mail and says so on the domain's record. The one
// thing a chain can say that is worse than "stranger".
func TestARevokedIdentityHoldsAndIsRecorded(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	fp1, pk1, priv1 := fpFor(t, dom, 1)

	rev, err := identity.SignRevocation(dom, priv1, nil, "key compromise", now, now.Add(time.Hour), fp1)
	if err != nil {
		t.Fatal(err)
	}
	r := &chainResolver{
		res: result(t, dom, now, 2), // some stranger signs now
		doc: docFor(t, dom, 2, []identity.Statement{rev}, now),
	}
	store := pinnedStore(t, dom, fp1, []byte(pk1), now)
	svc := peer.NewService(r, store, peer.Options{Now: func() time.Time { return now }})
	t.Cleanup(svc.Close)

	if _, err := svc.ResolveForEncryption(ctx, dom); err == nil {
		t.Fatal("mail went out under a revoked identity")
	}
	p, _ := store.GetPeer(ctx, dom)
	found := false
	for _, iss := range p.Issues {
		if iss.Code == mailkey.IssueRevoked {
			found = true
		}
	}
	if !found {
		t.Fatalf("the revocation left no trace on the domain's record: %+v", p.Issues)
	}
}

// A pin from before the public key rode along cannot verify any chain: the walk
// declines, the refusal stands, and a human decides — the pre-chain behaviour.
func TestALegacyPinWithoutItsKeyStaysAHumanDecision(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	fp1, _, priv1 := fpFor(t, dom, 1)
	_, _, priv2 := fpFor(t, dom, 2)
	stmt, err := identity.SignRotation(dom, priv1, priv2, now, now, now.Add(time.Hour*24*365))
	if err != nil {
		t.Fatal(err)
	}
	r := &chainResolver{
		res: result(t, dom, now, 2),
		doc: docFor(t, dom, 2, []identity.Statement{stmt}, now),
	}
	store := pinnedStore(t, dom, fp1, nil, now) // no stored key
	svc := peer.NewService(r, store, peer.Options{Now: func() time.Time { return now }})
	t.Cleanup(svc.Close)

	if _, err := svc.ResolveForEncryption(ctx, dom); err == nil {
		t.Fatal("a chain was accepted with no key to verify its first link against")
	}
}
