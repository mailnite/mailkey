/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package mailkey

import "time"

/*
Reviewable conditions, per peer.

Every withheld pin, refused response and held message is a fact about ONE
domain. Spec 07 §12 P4 puts them on that domain's record rather than only in a
log, because a log is something an operator reads after being told to, and the
whole difficulty here is that nobody tells them.

Two properties make the difference between review and noise:

  - COALESCED. The same failure repeats on every retry, and every message to
    that domain. An unbounded list of identical rows is not a history, it is a
    way of hiding the other seven conditions underneath the loud one. Occurrences
    fold into a count with a first- and last-seen.
  - CODED. Prose describes an incident; a code lets a surface group them, count
    them, translate them and offer the action that resolves them. The prose is
    kept alongside for a human, and is never parsed.
*/

// IssueCode names one reviewable condition. Stable across versions: it is
// persisted, translated, and matched on by surfaces.
type IssueCode string

const (
	// IssueSignerChanged: a domain we have PINNED is now signed by a different
	// identity. The manifest is otherwise valid, which is what makes this
	// serious rather than merely broken — it is the shape of both a legitimate
	// rotation and an authority compromise, and MKDP1 refuses to guess.
	IssueSignerChanged IssueCode = "signer-changed"
	// IssueProofMissing: a pinned domain answered without a usable proof. Mail
	// holds, because a pin that can be dropped by omitting a header is not a pin.
	IssueProofMissing IssueCode = "proof-missing"
	// IssuePinWithheld: long-term trust was deliberately NOT established. Not a
	// weaker pin — the refusal to create one while the evidence disagrees.
	IssuePinWithheld IssueCode = "pin-withheld"
	// IssueReplay: a manifest older than, or conflicting with, what we already
	// hold. Evidence of a replay or of a publisher with a broken clock.
	IssueReplay IssueCode = "replay"
	// IssueAuthorityUnstable: the authority alternates between different valid
	// manifests. MKDP1 invents no tie-break, so a human decides.
	IssueAuthorityUnstable IssueCode = "authority-unstable"
	// IssueDowngradeBlocked: the capability latch fired — this domain has
	// encrypted before, no key can be had, and cleartext was refused. The
	// silent-downgrade attack, caught.
	IssueDowngradeBlocked IssueCode = "downgrade-blocked"
	// IssueMailHeld: a submission could not be encrypted to this domain and was
	// not sent. The operator-visible consequence of everything above.
	IssueMailHeld IssueCode = "mail-held"
	// IssueRefreshFailed: discovery failed. The mildest condition here and the
	// most common — an unreachable authority is ordinary internet weather.
	IssueRefreshFailed IssueCode = "refresh-failed"
)

/*
Alerts reports whether this condition is worth interrupting an operator for.

Spec 07 §12 P4: "Held mail, a pinned domain whose authority changed signer, and
a withheld pin are worth waking someone for. An unsigned domain is not — it is
the majority of the internet."

The line is drawn at ACTIONABILITY, not severity. A refresh failure is often
worse for the sender than a withheld pin, and it is still not alerted, because
there is nothing an operator can do about someone else's outage and an alert
that fires routinely is an alert that gets ignored. Everything remains visible
on the peer's record either way; this only decides what pushes.
*/
func (c IssueCode) Alerts() bool {
	switch c {
	case IssueSignerChanged, IssuePinWithheld, IssueDowngradeBlocked, IssueMailHeld, IssueProofMissing:
		// ProofMissing only arises for a domain that is already PINNED, which
		// means an operator has decided they care about it. A pinned peer that
		// stops signing is precisely what they pinned it to be told about.
		return true
	default:
		// IssueRefreshFailed: someone else's outage, and nothing to do about it.
		// IssueReplay: evidence of a broken publisher clock more often than an
		// attack, and the manifest was refused either way.
		// IssueAuthorityUnstable: already has its own notification, emitted
		// where the instability is detected — alerting twice for one condition
		// is how a category gets muted.
		return false
	}
}

// PeerIssue is one condition on one peer, with how often and how recently.
type PeerIssue struct {
	Code      IssueCode `value:"code,omitempty"`
	FirstSeen time.Time `value:"firstSeen,omitempty"`
	LastSeen  time.Time `value:"lastSeen,omitempty"`
	// Count is every occurrence, not every stored row: the point of coalescing
	// is that "1,284 times since Tuesday" is the useful fact.
	Count uint32 `value:"count,omitempty"`
	// Detail is the most recent prose for a human. Never parsed, never matched.
	Detail string `value:"detail,omitempty"`
}

/*
MaxPeerIssues bounds the history.

There are eight codes, so a peer in total disarray fills the list exactly. The
cap exists for the case the enumeration grows later, and it evicts the LEAST
RECENT rather than the oldest-first-seen: a condition that started months ago
and still fires every hour is the live problem, and a first-seen ordering would
drop it in favour of something that happened once.
*/
const MaxPeerIssues = 8

/*
CoalesceIssue folds one occurrence into a peer's history.

Returns the new slice and whether this is the condition's FIRST occurrence,
which is the whole basis of "once per domain per condition rather than once per
message". The caller alerts on true and stays silent otherwise, so a domain that
holds four hundred messages overnight produces one notification.

Recurrence after a clear alerts again, deliberately: ClearIssue removes the row
when the condition stops holding, so the next occurrence is genuinely first. A
problem that comes back is news.
*/
func CoalesceIssue(issues []PeerIssue, code IssueCode, detail string, now time.Time) ([]PeerIssue, bool) {
	out := append([]PeerIssue(nil), issues...)
	for i := range out {
		if out[i].Code != code {
			continue
		}
		out[i].Count++
		out[i].LastSeen = now
		if detail != "" {
			out[i].Detail = detail
		}
		return out, false
	}
	out = append(out, PeerIssue{Code: code, FirstSeen: now, LastSeen: now, Count: 1, Detail: detail})
	for len(out) > MaxPeerIssues {
		stalest := 0
		for i := range out {
			if out[i].LastSeen.Before(out[stalest].LastSeen) {
				stalest = i
			}
		}
		out = append(out[:stalest], out[stalest+1:]...)
	}
	return out, true
}

// ClearIssue removes a condition that no longer holds, so its recurrence is
// reported as new rather than folded silently into a months-old row.
func ClearIssue(issues []PeerIssue, code IssueCode) []PeerIssue {
	out := make([]PeerIssue, 0, len(issues))
	for _, x := range issues {
		if x.Code != code {
			out = append(out, x)
		}
	}
	return out
}
