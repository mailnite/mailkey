/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/peer"
)

var hnow = time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)

func fpOf(b byte) mailkey.Fingerprint {
	var fp mailkey.Fingerprint
	for i := range fp {
		fp[i] = b
	}
	return fp
}

/*
THE invariant: a peer's health and its mail flow are separate axes.

The HTTPS manifest is the source of truth; DNS is corroboration (spec 07 §7).
A peer can be thoroughly incoherent and every message to it still goes out,
sealed and on time. If the assessment implied otherwise, an operator would read
"broken" as "my mail is stuck" and start intervening in a system that is working
— and the intervention available to them, clearing a pin, makes the incoherence
no better while risking the anchor.
*/
func TestIncoherenceIsVisibleAndNeverBlocksMail(t *testing.T) {
	p := &mailkey.Peer{
		Domain: "partner.test",
		Identity: mailkey.IdentityState{
			Status: mailkey.IdentityPinned, Fingerprint: fpOf(1),
			DNSFingerprint: fpOf(9), HasDNSFP: true, // DNS says something else entirely
		},
	}
	h := peer.Assess(p, hnow)
	if !h.Has(mailkey.HealthDNSIncoherent) {
		t.Fatalf("a DNS disagreement was not surfaced: %+v", h.Findings)
	}
	if h.DeliveryAffected {
		t.Fatal("an unauthenticated DNS record was reported as affecting delivery — the manifest is the source of truth")
	}
	if h.Level == mailkey.HealthOK {
		t.Fatal("the disagreement was hidden entirely; the operator has nothing to review")
	}
}

// Every diagnostic finding: visible, and none of them touches delivery.
func TestNoDiagnosticFindingEverAffectsDelivery(t *testing.T) {
	for _, f := range []mailkey.HealthFinding{
		mailkey.HealthUnsigned, mailkey.HealthUnpinned, mailkey.HealthDNSIncoherent,
		mailkey.HealthDNSAbsent, mailkey.HealthContested, mailkey.HealthUnstable,
		mailkey.HealthStale, mailkey.HealthUnreachable,
	} {
		if f.AffectsDelivery() {
			t.Errorf("%s would tell an operator their mail is held; it is a diagnostic", f)
		}
	}
	// And exactly the two that DO mean mail is not moving.
	for _, f := range []mailkey.HealthFinding{mailkey.HealthMailHeld, mailkey.HealthDowngradeBlocked} {
		if !f.AffectsDelivery() {
			t.Errorf("%s means messages are held and does not say so", f)
		}
	}
}

/*
TestHeldMailDoesNotRankAsBroken.

A domain whose mail is held is usually a domain whose peer state is otherwise
fine — the hold is this server refusing to downgrade, which is the protection
working. Ranking it "broken" would put the loudest colour on the correct
behaviour, and teach an operator to make it stop.
*/
func TestHeldMailDoesNotRankAsBroken(t *testing.T) {
	p := &mailkey.Peer{
		Domain:   "partner.test",
		Identity: mailkey.IdentityState{Status: mailkey.IdentityPinned, Fingerprint: fpOf(1)},
		Issues:   []mailkey.PeerIssue{{Code: mailkey.IssueDowngradeBlocked, Count: 12}},
	}
	h := peer.Assess(p, hnow)
	if !h.DeliveryAffected {
		t.Fatal("held mail was not reported as affecting delivery — the one thing the operator needs to know")
	}
	if h.Level == mailkey.HealthBroken {
		t.Fatal("a peer whose mail is held by working protection was ranked broken")
	}
}

// A pinned, coherent, signing peer is silent.
// Missing DNS is an indication, not a blocker: the peer's own administrator can
// publish the record, and until they do every message still goes out sealed.
func TestMissingDNSIsAnIndicationNotABlocker(t *testing.T) {
	p := &mailkey.Peer{
		Domain:    "partner.test",
		Identity:  mailkey.IdentityState{Status: mailkey.IdentityPinned, Fingerprint: fpOf(1)},
		Effective: &mailkey.ManifestRecord{ExpiresAt: hnow.Add(24 * time.Hour)},
	}
	h := peer.Assess(p, hnow)
	if !h.Has(mailkey.HealthDNSAbsent) {
		t.Fatalf("a peer publishing no corroborating record was reported as fully healthy: %+v", h.Findings)
	}
	if h.DeliveryAffected || !h.Encrypting {
		t.Fatal("a missing DNS record stopped mail; it is corroboration, not authority")
	}
}

func TestAHealthyPeerIsSilent(t *testing.T) {
	p := &mailkey.Peer{
		Domain: "partner.test",
		Identity: mailkey.IdentityState{
			Status: mailkey.IdentityPinned, Fingerprint: fpOf(1),
			DNSFingerprint: fpOf(1), HasDNSFP: true,
		},
	}
	if h := peer.Assess(p, hnow); h.Level != mailkey.HealthOK || len(h.Findings) != 0 || h.DeliveryAffected {
		t.Fatalf("a healthy peer reported %v at %v", h.Findings, h.Level)
	}
}

/*
TestAnUnsignedPeerIsDegradedNotBroken.

A domain that publishes no identity at all is the ordinary case during adoption —
most of the internet. Ranking it broken would make the Peers page a wall of red
that says nothing, and the one genuinely broken peer would be invisible in it.
*/
func TestAnUnsignedPeerIsDegradedNotBroken(t *testing.T) {
	h := peer.Assess(&mailkey.Peer{Domain: "old.test"}, hnow)
	if !h.Has(mailkey.HealthUnsigned) {
		t.Fatalf("an unsigned peer was not identified: %+v", h.Findings)
	}
	if h.Level != mailkey.HealthDegraded {
		t.Fatalf("an unsigned peer ranked %v; most of the internet lives here", h.Level)
	}
	if h.DeliveryAffected {
		t.Fatal("a domain that simply does not speak MKDP1 was reported as blocking mail")
	}
}

/*
TestADegradedPeerStillEncrypts is the sentence an operator needs the page to be
able to say: not healthy, and still sealing every message.

It is the common case during adoption — unpinned, or unsigned, or with a stale
DNS record — and "degraded" plus "not encrypting" are the two facts most easily
conflated. Left to inference, a warning colour reads as lost protection.
*/
func TestADegradedPeerStillEncrypts(t *testing.T) {
	p := &mailkey.Peer{
		Domain: "newpeer.test",
		// No identity at all: the ordinary state of most of the internet.
		Effective: &mailkey.ManifestRecord{ExpiresAt: hnow.Add(24 * time.Hour)},
	}
	h := peer.Assess(p, hnow)
	if h.Level == mailkey.HealthOK {
		t.Fatal("an unsigned peer was reported as healthy")
	}
	if !h.Encrypting {
		t.Fatal("a peer with a usable published key was not reported as encrypting — the page cannot say \"not healthy, still encrypting\"")
	}
	if h.DeliveryAffected {
		t.Fatal("an unsigned peer was reported as blocking mail")
	}
}

// A peer whose mail is held is, by definition, not encrypting it — nothing was
// sent at all.
func TestAHeldPeerIsNotReportedAsEncrypting(t *testing.T) {
	p := &mailkey.Peer{
		Domain:    "partner.test",
		Effective: &mailkey.ManifestRecord{ExpiresAt: hnow.Add(24 * time.Hour)},
		Issues:    []mailkey.PeerIssue{{Code: mailkey.IssueMailHeld, Count: 3}},
	}
	if h := peer.Assess(p, hnow); h.Encrypting {
		t.Fatal("a peer whose mail is held was reported as encrypting it")
	}
}
