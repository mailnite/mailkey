/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
)

const dom = "example.com"

var base = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, mailkey.Fingerprint) {
	t.Helper()
	pk, priv, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := identity.FingerprintOf(dom, pk)
	if err != nil {
		t.Fatal(err)
	}
	return pk, priv, fp
}

func rotate(t *testing.T, oldPriv, newPriv ed25519.PrivateKey, notBefore time.Time) identity.Statement {
	t.Helper()
	s, err := identity.SignRotation(dom, oldPriv, newPriv, notBefore, base, base.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

/*
TestBothSignaturesAreRequired is the construction, and each half of it stops a
complete break of pinning.

The OLD signature alone: a stolen old key installs an attacker's identity — the
exact compromise a rotation is supposed to let a domain recover FROM.

The NEW signature alone: anyone who can serve the resource claims succession, and
pinning collapses back into trusting the transport.
*/
func TestBothSignaturesAreRequired(t *testing.T) {
	oldPK, oldPriv, _ := keypair(t)
	_, newPriv, _ := keypair(t)
	good := rotate(t, oldPriv, newPriv, base)

	if err := identity.VerifyStatement(good, oldPK); err != nil {
		t.Fatalf("a correctly signed rotation was refused: %v", err)
	}

	noNew := good
	noNew.NewSignature = nil
	if err := identity.VerifyStatement(noNew, oldPK); err == nil {
		t.Fatal("a rotation with no proof of possession was accepted — anyone serving the resource could claim succession")
	}

	noOld := good
	noOld.OldSignature = nil
	if err := identity.VerifyStatement(noOld, oldPK); err == nil {
		t.Fatal("a rotation the old identity never authorized was accepted")
	}
}

/*
TestTheStatementCannotNameAnIdentityItDoesNotCarry.

new_fp is RECOMPUTED from new_pk. Without that, a statement could advertise a
fingerprint an operator recognises while carrying an attacker's key, and every
verifier that trusted the field would pin the wrong thing while its logs showed
the right one.
*/
func TestTheStatementCannotNameAnIdentityItDoesNotCarry(t *testing.T) {
	oldPK, oldPriv, oldFP := keypair(t)
	newPK, newPriv, _ := keypair(t)
	_, _, decoyFP := keypair(t)

	// A publisher SIGNING a mismatch, which is the adversary that exists: both
	// signatures verify, and the statement still lies about which identity it
	// carries. Mutating a field on a signed statement would only prove the
	// signature covers it, which is a different test.
	lying, err := identity.SignStatement(identity.Statement{
		Type: identity.RotationType, Version: mailkey.Version, Domain: dom,
		OldFP: oldFP, NewFP: decoyFP, NewAlg: identity.Alg, NewPK: newPK,
		NotBefore: base, CreatedAt: base, ExpiresAt: base.Add(365 * 24 * time.Hour),
	}, oldPriv, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.VerifyStatement(lying, oldPK); err == nil {
		t.Fatal("a correctly signed statement naming one identity while carrying another was accepted")
	}
}

// The signature covers every field: changing any of them must invalidate it.
func TestEveryFieldIsSigned(t *testing.T) {
	oldPK, oldPriv, _ := keypair(t)
	_, newPriv, _ := keypair(t)
	good := rotate(t, oldPriv, newPriv, base)

	for name, mut := range map[string]func(*identity.Statement){
		"domain":     func(s *identity.Statement) { s.Domain = "evil.test" },
		"not_before": func(s *identity.Statement) { s.NotBefore = base.Add(time.Hour) },
		"expires_at": func(s *identity.Statement) { s.ExpiresAt = base.Add(99 * time.Hour) },
		"created_at": func(s *identity.Statement) { s.CreatedAt = base.Add(-time.Hour) },
		"type":       func(s *identity.Statement) { s.Type = identity.RevocationType },
		"version":    func(s *identity.Statement) { s.Version = "MKDP9" },
	} {
		t.Run(name, func(t *testing.T) {
			s := good
			mut(&s)
			if err := identity.VerifyStatement(s, oldPK); err == nil {
				t.Fatalf("%s is not covered by the signature", name)
			}
		})
	}
}

/*
TestTheWalkStartsFromThePinNotTheHead.

A verifier that walked backwards from the head of the chain would accept any
chain ending wherever the server liked — the transport deciding the pin, which is
the one thing the whole extension exists to prevent. So a chain that does not
descend from OUR pin moves nothing.
*/
func TestTheWalkStartsFromThePinNotTheHead(t *testing.T) {
	ourPK, _, ourFP := keypair(t)
	_, strangerPriv, _ := keypair(t)
	_, attackerPriv, attackerFP := keypair(t)

	// A perfectly valid chain — between two identities that are not ours.
	foreign := rotate(t, strangerPriv, attackerPriv, base)

	got, err := identity.WalkChain(ourFP, ourPK, []identity.Statement{foreign}, base)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != ourFP || got.Applied != 0 {
		t.Fatalf("a chain that never descended from our pin moved it to %x", got.Fingerprint)
	}
	if got.Fingerprint == attackerFP {
		t.Fatal("the pin followed a foreign chain to the attacker's identity")
	}
}

/*
TestOrderingComesFromSignaturesNotFields: the chain may arrive in any order.

Each step looks for the statement that descends from the identity currently in
effect, so nothing about the slice's order — or a convenient not_before — can
advance the walk. That is the difference between this and the seq value MKDP1
removed: a counter anyone can set orders by assertion, a chain orders by descent.
*/
func TestOrderingComesFromSignaturesNotFields(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	_, priv2, fp2 := keypair(t)
	_, priv3, fp3 := keypair(t)

	first := rotate(t, priv1, priv2, base)
	second := rotate(t, priv2, priv3, base.Add(time.Hour))

	// Presented backwards, and with a decoy whose not_before is the newest.
	_, decoyPriv, _ := keypair(t)
	_, decoyNewPriv, _ := keypair(t)
	decoy := rotate(t, decoyPriv, decoyNewPriv, base.Add(48*time.Hour))

	got, err := identity.WalkChain(fp1, pk1, []identity.Statement{decoy, second, first}, base.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != fp3 || got.Applied != 2 {
		t.Fatalf("the walk ended at %x after %d steps, want fp3 after 2", got.Fingerprint, got.Applied)
	}
	if got.Fingerprint == fp2 {
		t.Fatal("the walk stopped at the intermediate identity")
	}
}

// A transition signed but not yet effective is skipped, not rejected: staging a
// rotation ahead of time is a supported operation, not an error.
func TestAFutureTransitionDoesNotApplyYet(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	_, priv2, fp2 := keypair(t)
	future := rotate(t, priv1, priv2, base.Add(24*time.Hour))

	got, err := identity.WalkChain(fp1, pk1, []identity.Statement{future}, base)
	if err != nil {
		t.Fatalf("a staged rotation was reported as an error: %v", err)
	}
	if got.Applied != 0 || got.Fingerprint != fp1 {
		t.Fatal("a rotation applied before its not_before")
	}
	// ...and applies once it is due.
	got, err = identity.WalkChain(fp1, pk1, []identity.Statement{future}, base.Add(25*time.Hour))
	if err != nil || got.Fingerprint != fp2 {
		t.Fatalf("the rotation did not apply when due: %+v (%v)", got, err)
	}
}

/*
TestAForgedLinkBreaksTheChainRatherThanBeingSkipped.

A statement that CLAIMS to descend from the current identity and does not verify
is not noise to step over. Skipping it would mean choosing whichever link
happened to verify next — letting an attacker who can inject one statement steer
the walk by making the legitimate one unattractive.
*/
func TestAForgedLinkBreaksTheChainRatherThanBeingSkipped(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	_, priv2, _ := keypair(t)
	_, attackerPriv, _ := keypair(t)

	legit := rotate(t, priv1, priv2, base)
	forged := rotate(t, attackerPriv, attackerPriv, base)
	forged.OldFP = fp1 // claims to descend from our pin; signed by neither of ours

	_, err := identity.WalkChain(fp1, pk1, []identity.Statement{forged, legit}, base.Add(time.Hour))
	if err == nil {
		t.Fatal("a forged link claiming descent from the pin was silently skipped")
	}
	if !errors.Is(err, identity.ErrChainBroken) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// §5.2: a chain must be bounded. An unbounded one is a parsing budget an
// attacker chooses.
func TestTheChainIsBounded(t *testing.T) {
	pk1, _, fp1 := keypair(t)
	chain := make([]identity.Statement, identity.MaxChainEntries+1)
	if _, err := identity.WalkChain(fp1, pk1, chain, base); !errors.Is(err, identity.ErrChainTooLong) {
		t.Fatalf("an over-long chain was walked: %v", err)
	}
}

/*
TestRevocationMayComeFromEitherAuthority.

A revocation is often needed precisely BECAUSE the old key is gone — stolen,
lost, or destroyed — so requiring the revoked identity to sign its own
withdrawal would make the case that matters most impossible to express.
*/
func TestRevocationMayComeFromEitherAuthority(t *testing.T) {
	oldPK, oldPriv, oldFP := keypair(t)
	_, successorPriv, _ := keypair(t)

	self, err := identity.SignRevocation(dom, oldPriv, nil, "key compromise", base, base.Add(10*365*24*time.Hour), oldFP)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.VerifyStatement(self, oldPK); err != nil {
		t.Fatalf("an identity could not revoke itself: %v", err)
	}

	bySuccessor, err := identity.SignRevocation(dom, nil, successorPriv, "old key destroyed", base, base.Add(10*365*24*time.Hour), oldFP)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.VerifyStatement(bySuccessor, oldPK); err != nil {
		t.Fatalf("a successor could not revoke a key that is already gone: %v", err)
	}

	// But nobody's authority is not an authority.
	unsigned := self
	unsigned.OldSignature, unsigned.NewSignature = nil, nil
	if err := identity.VerifyStatement(unsigned, oldPK); err == nil {
		t.Fatal("an unsigned revocation was accepted — anyone could withhold any domain's identity")
	}
}

/*
TestRevocationIsReportedNotSilentlyTreatedAsNoKey.

"We have nothing" and "we were told to stop" call for different actions: the
first waits, the second acts. Collapsing them would turn a compromise
announcement into an outage nobody investigates.
*/
func TestRevocationIsReportedNotSilentlyTreatedAsNoKey(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	rev, err := identity.SignRevocation(dom, priv1, nil, "key compromise", base, base.Add(10*365*24*time.Hour), fp1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity.WalkChain(fp1, pk1, []identity.Statement{rev}, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Fatal("a revoked identity walked out as ordinary")
	}
	if got.Reason != "key compromise" {
		t.Fatalf("the signed reason was lost: %q", got.Reason)
	}
}

// A revocation naming a successor both withdraws the old identity and
// introduces the new one — the successor is emphatically NOT revoked.
func TestARevocationWithASuccessorMovesThePin(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	_, priv2, fp2 := keypair(t)
	rev, err := identity.SignRevocation(dom, priv1, priv2, "planned replacement", base, base.Add(10*365*24*time.Hour), fp1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity.WalkChain(fp1, pk1, []identity.Statement{rev}, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != fp2 {
		t.Fatalf("the successor did not take effect: %x", got.Fingerprint)
	}
	if got.Revoked {
		t.Fatal("the SUCCESSOR was reported as revoked — mail to a healthy identity would stop")
	}
}

/*
TestARevocationDoesNotLapseIntoTrust.

§5.1: "stop using this" has to outlive the thing it refers to. A verifier that
let a revocation expire would resurrect trust in a key someone announced was
compromised — silently, on a timer the publisher set before they knew they would
ever need it. Only a later signed statement ends a revocation. Never the clock.
*/
func TestARevocationDoesNotLapseIntoTrust(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	rev, err := identity.SignRevocation(dom, priv1, nil, "key compromise", base, base.Add(time.Hour), fp1)
	if err != nil {
		t.Fatal(err)
	}
	// Long after the statement's own expires_at.
	got, err := identity.WalkChain(fp1, pk1, []identity.Statement{rev}, base.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Fatal("a revocation lapsed and the compromised identity became trusted again")
	}
}

// A lapsed ROTATION does stop applying: it is a plan that did not happen, not a
// warning, and nothing is made unsafe by ignoring it.
func TestALapsedRotationStopsApplying(t *testing.T) {
	pk1, priv1, fp1 := keypair(t)
	_, priv2, _ := keypair(t)
	s, err := identity.SignRotation(dom, priv1, priv2, base, base, base.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := identity.WalkChain(fp1, pk1, []identity.Statement{s}, base.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Applied != 0 || got.Fingerprint != fp1 {
		t.Fatal("a lapsed rotation still moved the pin")
	}
}
