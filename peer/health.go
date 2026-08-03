/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer

import (
	"time"

	"github.com/mailnite/mailkey"
)

/*
Assess derives a peer's health from state that already exists.

A pure function over the stored record, deliberately: health is a VIEW, and
computing it anywhere that could influence a send would eventually let it. The
queue asks the resolver what to do with a message; it does not ask this, and
nothing here is reachable from the delivery path.

The delivery answer comes from the peer's ISSUE record — what actually happened
to real messages — not from inferring it. "Is mail held" is a fact this server
observed, and deriving it from identity state would mean guessing at something
already known, and guessing conservatively enough to alarm operators about
domains whose mail is flowing fine.
*/
func Assess(p *mailkey.Peer, now time.Time) mailkey.Health {
	var h mailkey.Health
	if p == nil {
		return h
	}

	id := p.Identity
	switch {
	case id.Status == mailkey.IdentityPinned:
		// An anchor exists. Nothing here downgrades that.
	case id.Status == mailkey.IdentityContested:
		h.Findings = append(h.Findings, mailkey.HealthContested)
	case hasEffectiveProof(p):
		h.Findings = append(h.Findings, mailkey.HealthUnpinned)
	default:
		// No proof at all. The ordinary state of most of the internet, and the
		// reason this is a finding rather than a fault.
		h.Findings = append(h.Findings, mailkey.HealthUnsigned)
	}

	/*
		DNS wrong and DNS missing are both indications, and both are facts about
		the PEER rather than about us — which is precisely why they are worth
		showing: that domain's own administrator can correct either one.

		Neither touches delivery. A pin is born from a valid proof whether DNS
		corroborates it or says nothing at all, and an unauthenticated record
		that disagrees with an authenticated manifest loses to the manifest.
	*/
	switch {
	case !id.HasDNSFP:
		h.Findings = append(h.Findings, mailkey.HealthDNSAbsent)
	case id.Status == mailkey.IdentityPinned && id.DNSFingerprint != id.Fingerprint:
		h.Findings = append(h.Findings, mailkey.HealthDNSIncoherent)
	}

	if p.AuthorityUnstable {
		h.Findings = append(h.Findings, mailkey.HealthUnstable)
	}
	if p.Effective != nil && !p.Effective.ExpiresAt.IsZero() && !p.Effective.ExpiresAt.After(now) {
		h.Findings = append(h.Findings, mailkey.HealthStale)
	}

	// What actually happened to mail, read from the record rather than inferred.
	for _, iss := range p.Issues {
		switch iss.Code {
		case mailkey.IssueMailHeld:
			h.Findings = append(h.Findings, mailkey.HealthMailHeld)
		case mailkey.IssueDowngradeBlocked:
			h.Findings = append(h.Findings, mailkey.HealthDowngradeBlocked)
		case mailkey.IssueRefreshFailed:
			h.Findings = append(h.Findings, mailkey.HealthUnreachable)
		}
	}

	for _, f := range h.Findings {
		if f.AffectsDelivery() {
			h.DeliveryAffected = true
		}
	}
	/*
		Whether mail to this peer is actually being sealed, which is a different
		question from whether the peer looks tidy. A usable published key is all
		it takes — an unpinned identity, a DNS record advertising something
		else, or no identity proof at all cost the peer health findings and cost
		the message nothing.
	*/
	h.Encrypting = !h.DeliveryAffected && p.Effective != nil &&
		(p.Effective.ExpiresAt.IsZero() || p.Effective.ExpiresAt.After(now))
	h.Level = levelOf(h.Findings)
	return h
}

/*
hasEffectiveProof reports whether this peer has ever produced a usable identity.

Read from the IDENTITY state rather than from the manifest record, because the
record does not carry the signer — the identity is kept separately, on purpose
(a manifest is re-issued often, an identity lasts years). A peer that has been
verified against an identity has one; one that never has does not sign.
*/
func hasEffectiveProof(p *mailkey.Peer) bool {
	var zero mailkey.Fingerprint
	return p.Identity.Fingerprint != zero || p.Identity.LastVerifiedManifestID != mailkey.ManifestID{}
}

/*
levelOf ranks the findings.

Broken is reserved for a peer whose own advertisement does not hold together —
an authority serving different valid manifests, an expired one it never
replaced, a contested identity. Degraded is everything an operator would like to
improve and nothing is wrong with: unpinned, unsigned, no DNS.

Held mail does NOT raise the level, and that is the whole point. A domain whose
mail is held is usually a domain whose peer state is otherwise fine — the hold
is this server refusing to downgrade, which is the protection working. Ranking
it as "broken" would put the loudest colour on the correct behaviour.
*/
func levelOf(fs []mailkey.HealthFinding) mailkey.HealthLevel {
	level := mailkey.HealthOK
	for _, f := range fs {
		switch f {
		case mailkey.HealthUnstable, mailkey.HealthStale, mailkey.HealthContested, mailkey.HealthUnreachable:
			level = mailkey.HealthBroken
		case mailkey.HealthUnsigned, mailkey.HealthUnpinned, mailkey.HealthDNSIncoherent, mailkey.HealthDNSAbsent:
			if level != mailkey.HealthBroken {
				level = mailkey.HealthDegraded
			}
		}
	}
	return level
}
