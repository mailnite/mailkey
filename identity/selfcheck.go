/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity

import "github.com/mailnite/mailkey"

/*
Publisher self-check (spec 07 §9).

A domain should find its own advertisement broken rather than learn about it from
correspondents, because by then the damage is already distributed: every sender
who fetched during the window has either failed to pin or pinned something wrong,
and a pin is not a cache — it persists.

FOUR values, and the reason there are four rather than two is that each pair of
adjacent ones fails differently:

	Configured  what this server is configured to sign with
	Served      what its own handler actually returns
	External    what the world's HTTPS fetch returns
	DNS         what the world's resolvers see

Configured ≠ Served is a deployment that half-applied — a reload that did not, a
key file swapped under a running process. Served ≠ External is something in
front of the server: a proxy, a stale CDN object, an interception. External ≠
DNS is an advertisement someone forgot to update, which is the mildest and the
most common.

Comparing only the ends would find "something is wrong" and nothing about where,
which for an operator at 3am is barely better than the correspondent's email.
*/

// SelfCheckInput is the four observations. A zero fingerprint means "not
// observed" — the check reports that as unknown rather than as a mismatch,
// because a DNS record that does not exist is a choice (§7 makes DNS optional)
// while one that disagrees is a problem.
type SelfCheckInput struct {
	Configured mailkey.Fingerprint
	Served     mailkey.Fingerprint
	External   mailkey.Fingerprint
	DNS        mailkey.Fingerprint
	HasDNS     bool
	// DNSSECValidated records whether the DNS answer was validated. It is
	// recorded, never required: §7 keeps DNS corroborating, and making the
	// check depend on it would let a resolver outage look like a mismatch.
	DNSSECValidated bool
}

// SelfCheckFinding names one discrepancy. Coded, so a dashboard can group and
// translate them and an operator can be told what to do rather than what differs.
type SelfCheckFinding string

const (
	// SelfCheckNotServing: the handler returns no identity at all.
	SelfCheckNotServing SelfCheckFinding = "not-serving"
	// SelfCheckServedMismatch: configured ≠ served. A deployment that
	// half-applied — the server is signing with something other than what it
	// was told to.
	SelfCheckServedMismatch SelfCheckFinding = "served-mismatch"
	// SelfCheckExternalMismatch: served ≠ external. Something in front of the
	// server is answering: a proxy, a stale cache, or an interception. This is
	// the finding that matters most and the one a local-only check cannot see.
	SelfCheckExternalMismatch SelfCheckFinding = "external-mismatch"
	// SelfCheckExternalUnreachable: the outside world could not fetch it.
	SelfCheckExternalUnreachable SelfCheckFinding = "external-unreachable"
	// SelfCheckDNSMismatch: DNS advertises a different identity. Corroboration
	// disagreeing, which withholds pins for every first-contact sender.
	SelfCheckDNSMismatch SelfCheckFinding = "dns-mismatch"
	// SelfCheckDNSAbsent: no DNS advertisement. Not an error — §7 makes it
	// optional — but worth showing, since it is the difference between a
	// sender pinning on first contact and merely encrypting.
	SelfCheckDNSAbsent SelfCheckFinding = "dns-absent"
	// SelfCheckDNSSECUnvalidated: DNS answered without DNSSEC validation.
	SelfCheckDNSSECUnvalidated SelfCheckFinding = "dnssec-unvalidated"
)

// Blocking reports whether a finding should stop a new identity from being
// activated. §9: the check runs BEFORE activation, and activating over a
// mismatch publishes an identity the world cannot see.
//
// The DNS findings are not blocking: DNS is corroboration, never authority, and
// letting a resolver disagreement block activation would hand anyone who can
// disturb DNS a veto over a domain's key management.
func (f SelfCheckFinding) Blocking() bool {
	switch f {
	case SelfCheckNotServing, SelfCheckServedMismatch, SelfCheckExternalMismatch, SelfCheckExternalUnreachable:
		return true
	default:
		return false
	}
}

// SelfCheckResult is what the dashboard shows.
type SelfCheckResult struct {
	Findings []SelfCheckFinding
	// OK is true when nothing blocking was found. DNS findings leave it true:
	// they are worth showing and must not stop a rotation.
	OK bool
}

// Blocked reports whether activation must not proceed.
func (r SelfCheckResult) Blocked() bool {
	for _, f := range r.Findings {
		if f.Blocking() {
			return true
		}
	}
	return false
}

/*
SelfCheck compares the four values.

External is checked against SERVED rather than against configured, deliberately.
If the handler is serving the wrong thing, the external mismatch is a
consequence, not a second fault, and reporting both would have an operator chase
a proxy that is faithfully relaying a server that is already wrong.
*/
func SelfCheck(in SelfCheckInput) SelfCheckResult {
	var out SelfCheckResult
	var zero mailkey.Fingerprint

	if in.Served == zero {
		out.Findings = append(out.Findings, SelfCheckNotServing)
	} else if in.Configured != zero && in.Configured != in.Served {
		out.Findings = append(out.Findings, SelfCheckServedMismatch)
	}

	switch {
	case in.External == zero:
		out.Findings = append(out.Findings, SelfCheckExternalUnreachable)
	case in.Served != zero && in.External != in.Served:
		out.Findings = append(out.Findings, SelfCheckExternalMismatch)
	}

	switch {
	case !in.HasDNS || in.DNS == zero:
		out.Findings = append(out.Findings, SelfCheckDNSAbsent)
	case in.Served != zero && in.DNS != in.Served:
		out.Findings = append(out.Findings, SelfCheckDNSMismatch)
	case !in.DNSSECValidated:
		out.Findings = append(out.Findings, SelfCheckDNSSECUnvalidated)
	}

	out.OK = !out.Blocked()
	return out
}
