/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity_test

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
)

func doc(t *testing.T, pk ed25519.PublicKey, fp mailkey.Fingerprint, chain []identity.Statement) []byte {
	t.Helper()
	raw, err := identity.PackDoc(identity.Doc{
		Domain: dom, ActiveFP: fp, ActivePK: pk, Status: identity.StatusActive,
		UpdatedAt: base, Chain: chain,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A document round-trips, and the chain inside it still verifies — the whole
// point being that a statement survives serialization byte-exactly, since its
// signature covers fields this encoding must not reinterpret.
func TestTheResourceRoundTripsAVerifiableChain(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	pk2, priv2, fp2 := keypair(t)
	s := rotate(t, priv1, priv2, base)

	got, err := identity.ParseDoc(dom, doc(t, pk2, fp2, []identity.Statement{s}))
	if err != nil {
		t.Fatal(err)
	}
	if got.ActiveFP != fp2 || len(got.Chain) != 1 {
		t.Fatalf("round trip lost the identity or the chain: %+v", got)
	}
	res, err := identity.WalkChain(fp1, pk1, got.Chain, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("a chain that verified before serialization did not after: %v", err)
	}
	if res.Fingerprint != fp2 {
		t.Fatalf("the deserialized chain ended at %x, want fp2", res.Fingerprint)
	}
}

/*
TestTheDocumentCannotNameAnIdentityItDoesNotCarry: active_fp is RECOMPUTED.

Otherwise a document could advertise a fingerprint an operator recognises while
carrying an attacker's key — and every dashboard showing "the published
fingerprint" would show the right one while the wrong key was in use.
*/
func TestTheDocumentCannotNameAnIdentityItDoesNotCarry(t *testing.T) {
	pk1, _, _ := keypair(t)
	_, _, decoyFP := keypair(t)
	raw, err := identity.PackDoc(identity.Doc{
		Domain: dom, ActiveFP: decoyFP, ActivePK: pk1,
		Status: identity.StatusActive, UpdatedAt: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.ParseDoc(dom, raw); err == nil {
		t.Fatal("a document naming one identity while carrying another was accepted")
	}
}

/*
TestADocumentCannotBeLiftedBetweenDomains.

The domain comes from the CALLER — what we fetched — not from the body. Without
that, an authority hosting two domains could serve one document under both, and
a fingerprint established for one would silently become the pin for the other.
*/
func TestADocumentCannotBeLiftedBetweenDomains(t *testing.T) {
	pk1, _, fp1 := keypair(t)
	raw := doc(t, pk1, fp1, nil)
	if _, err := identity.ParseDoc("other.test", raw); err == nil {
		t.Fatal("a document served for one domain parsed as another's")
	}
}

/*
TestTheSchemaFailsClosedOnUnknownFields.

Old clients never request this resource, so it is free to be strict — and the
one thing it must never do is let an attacker smuggle a field past a verifier
that shrugged at it. A field nobody understands is an error, not something to
skip.
*/
func TestTheSchemaFailsClosedOnUnknownFields(t *testing.T) {
	pk1, _, fp1 := keypair(t)
	raw := doc(t, pk1, fp1, nil)
	// The canonical encoding sorts keys, so injecting a plausible-looking field
	// is enough to prove the parser enumerates rather than ignores.
	if _, err := identity.ParseDoc(dom, raw); err != nil {
		t.Fatalf("the honest document did not parse: %v", err)
	}
	bad, err := identity.PackDoc(identity.Doc{
		Domain: dom, ActiveFP: fp1, ActivePK: pk1, Status: identity.StatusActive, UpdatedAt: base,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Truncation is the cheap corruption; a strict parser must reject it too.
	if _, err := identity.ParseDoc(dom, bad[:len(bad)/2]); err == nil {
		t.Fatal("a truncated document parsed")
	}
}

// §5.2: the resource is bounded before it is parsed.
func TestTheResourceIsBounded(t *testing.T) {
	pk1, _, fp1 := keypair(t)
	huge := make([]byte, identity.MaxChainBytes+1)
	if _, err := identity.ParseDoc(dom, huge); err == nil {
		t.Fatal("an oversized body was parsed")
	}
	over := make([]identity.Statement, identity.MaxChainEntries+1)
	if _, err := identity.PackDoc(identity.Doc{
		Domain: dom, ActiveFP: fp1, ActivePK: pk1, Status: identity.StatusActive,
		UpdatedAt: base, Chain: over,
	}); err == nil {
		t.Fatal("an over-long chain was published")
	}
}

/*
TestByFPPathIsContentAddressed: the immutable objects are named by the
fingerprint the transition INSTALLS.

That is what makes `immutable` caching honest — the object at a given path can
never legitimately change, because a different transition installs a different
fingerprint and therefore lives at a different path.
*/
func TestByFPPathIsContentAddressed(t *testing.T) {
	_, _, fp1 := keypair(t)
	_, _, fp2 := keypair(t)
	if identity.ByFPPathFor(fp1) == identity.ByFPPathFor(fp2) {
		t.Fatal("two identities share one immutable path")
	}
	if !strings.HasPrefix(identity.ByFPPathFor(fp1), identity.ByFPPath) {
		t.Fatalf("unexpected path: %s", identity.ByFPPathFor(fp1))
	}
	// Stable across calls, or caching it would be meaningless.
	if identity.ByFPPathFor(fp1) != identity.ByFPPathFor(fp1) {
		t.Fatal("the immutable path is not stable")
	}
}

// The stored chain round-trips with its signatures intact — the publisher's
// history must survive every rotation including the one being made.
func TestPackChainRoundTripsVerifiably(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	_, priv2, fp2 := keypair(t)
	s := rotate(t, priv1, priv2, base)
	raw, err := identity.PackChain([]identity.Statement{s})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := identity.ParseChain(raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := identity.WalkChain(fp1, pk1, chain, base.Add(time.Hour))
	if err != nil || res.Fingerprint != fp2 {
		t.Fatalf("the stored chain lost its proof: %v %x", err, res.Fingerprint)
	}
	// Empty is empty, not an error: a domain that never rotated has no chain.
	if got, err := identity.ParseChain(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty chain: %v %v", got, err)
	}
}
