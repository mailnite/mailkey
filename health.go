/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package mailkey

/*
Peer health: what is TRUE about a peer, kept separate from what happens to MAIL.

One distinction worth stating, because it is easy to collapse: how a peer was
DISCOVERED is not how well it is SET UP. Manual entry, DNS and the Mail-Key
header are three equally valid ways to learn a domain exists, and the HTTPS
manifest is what establishes trust in it. So a peer an operator typed in is
discovered as completely as one found by TXT lookup.

But a domain that publishes no corroborating record is still less verifiable
than one that does — an attacker holding only the TLS path has one channel to
manipulate instead of two — and that is a fact about the PEER, not about us. It
is reported for the same reason everything else here is: so somebody, usually
that domain's own administrator, can fix it. It costs the message nothing.

These are two axes and merging them is the mistake this type exists to prevent.
A peer can be thoroughly incoherent — DNS advertising one identity while its
authority signs with another, no proof at all, a pin withheld for months — and
every message to it still goes out, sealed, on time. The HTTPS manifest is the
source of truth (spec 07 §7); DNS is corroboration and can never be a reason to
stop sending.

Presented as one number, an operator reading "unhealthy" concludes their mail is
stuck and starts intervening in a system that is working. That is worse than
showing nothing: it converts a diagnostic into an outage, and the intervention
available to them — clearing a pin — makes the incoherence they can see no
better while risking the anchor they cannot.

So Level says how much is wrong, DeliveryAffected says whether anything is
actually held, and the second is not derived from the first.
*/

// HealthLevel is how far a peer's state is from what it should be.
type HealthLevel int

const (
	// HealthUnknown is the zero value: nothing observed yet.
	HealthUnknown HealthLevel = iota
	// HealthOK: signed, pinned, coherent.
	HealthOK
	// HealthDegraded: something is wrong that an operator should see and that
	// does NOT stop mail — an unpinned peer, a DNS disagreement, a domain that
	// does not sign at all. Most of the internet lives here during adoption.
	HealthDegraded
	// HealthBroken: the peer's own advertisement is inconsistent or unusable.
	// Still says nothing about delivery on its own.
	HealthBroken
)

func (h HealthLevel) String() string {
	switch h {
	case HealthOK:
		return "ok"
	case HealthDegraded:
		return "degraded"
	case HealthBroken:
		return "broken"
	default:
		return "unknown"
	}
}

// HealthFinding names one thing an operator can see about a peer. Coded so a
// surface can group, translate and act on it.
type HealthFinding string

const (
	// Diagnostics — visible, never a reason mail stops.
	HealthUnsigned      HealthFinding = "unsigned"       // publishes no identity proof at all
	HealthUnpinned      HealthFinding = "unpinned"       // signs, but no anchor established here
	HealthDNSIncoherent HealthFinding = "dns-incoherent" // DNS advertises a different identity
	HealthDNSAbsent     HealthFinding = "dns-absent"     // no corroborating record published
	HealthContested     HealthFinding = "contested"      // pinning deliberately withheld
	HealthUnstable      HealthFinding = "unstable"       // authority alternates between valid manifests
	HealthStale         HealthFinding = "stale"          // the cached manifest has expired
	HealthUnreachable   HealthFinding = "unreachable"    // the authority could not be fetched

	// Delivery-affecting. These are the ONLY two that mean mail is not moving.
	HealthMailHeld         HealthFinding = "mail-held"         // an identity refusal is holding messages
	HealthDowngradeBlocked HealthFinding = "downgrade-blocked" // the latch is holding messages
)

// AffectsDelivery reports whether this finding means mail is actually held.
//
// Only two do. Everything else is something to look at, and an implementation
// that let any of the others gate the queue would have turned a peer's
// misconfiguration into this server's outage.
func (f HealthFinding) AffectsDelivery() bool {
	return f == HealthMailHeld || f == HealthDowngradeBlocked
}

// Health is the assessment shown on the Peers page.
type Health struct {
	Level    HealthLevel
	Findings []HealthFinding
	/*
		DeliveryAffected is the question an operator is actually asking, and it
		is answered separately from Level on purpose.

		A degraded peer delivers. A broken peer usually delivers. Reading the
		level as a delivery signal is the misunderstanding this field exists to
		make impossible — it is cheaper to answer the question than to hope
		nobody infers the answer from the colour.
	*/
	DeliveryAffected bool
	/*
		Encrypting reports that outbound mail to this peer is being SEALED right
		now — it has a usable published key.

		Stated rather than left to be inferred, because "degraded" and "not
		encrypting" are the two things an operator most easily conflates, and
		the common case is a peer that is both degraded and encrypting
		perfectly well: unpinned, or unsigned, or with DNS advertising
		something stale. The page should be able to say "not healthy, still
		encrypting" in those words instead of showing a warning colour and
		leaving the reader to guess what it costs them.

		Independent of Level and of DeliveryAffected. A peer can be degraded and
		encrypting; broken and encrypting; held and — by definition — not.
	*/
	Encrypting bool
}

// Has reports whether the assessment carries a finding.
func (h Health) Has(f HealthFinding) bool {
	for _, x := range h.Findings {
		if x == f {
			return true
		}
	}
	return false
}
