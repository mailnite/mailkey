/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package peer is the source-neutral Peer model: one record per email domain, no
matter how many places observed it, and the rules for moving it between states.

The state transitions live here as PURE FUNCTIONS over a *mailkey.Peer. A Store
implementation — in memory, badger, SQL — supplies only persistence and
atomicity and calls these to mutate the record, so every backend shares one
implementation of the protocol's semantics instead of reimplementing them.

The semantics that matter, all of which exist to keep untrusted input from
deciding anything:

  - An observation NEVER installs a key. It records that a domain speaks MKDP1
    and which manifest id the observer saw, and it can schedule a fetch. That
    is the entirety of its power.

  - There is no arbitration between observations. When DNS says B, a header
    says C and the authority answers D, D is effective and B and C become
    stale — no maximum, no vote, no source precedence. An ordering rule here
    would be an ordering rule an attacker could aim.

  - A fetched manifest replaces the effective one WHOLE and atomically. The
    previous one becomes historical for diagnostics; the private key it names
    is retained separately by the receiver, which is what lets delayed mail
    still open.

  - An authority that alternates between different valid manifests is reported
    as unstable rather than resolved. Choosing between them would require
    inventing exactly the ordering rule MKDP1 removed.
*/
package peer

import (
	"time"

	"github.com/mailnite/mailkey"
)

// HistoryLimit bounds retained historical manifests per peer. Diagnostics need
// a few; an unbounded list would let a rotating (or flapping) authority grow
// our storage without limit.
const HistoryLimit = 8

// RefreshBefore is how long before expiry a manifest is considered due for
// refresh, so the outbound path finds a valid manifest rather than a race.
const RefreshBefore = 6 * time.Hour

// instabilityWindow is the span within which repeated manifest changes look
// like an unstable authority rather than ordinary rotation.
const instabilityWindow = time.Hour

// New returns a freshly discovered peer.
func New(domain string) *mailkey.Peer {
	return &mailkey.Peer{Domain: domain, State: mailkey.StateDiscovered, Policy: mailkey.PolicyAuto}
}

// Install makes a fetched manifest the peer's effective one. It is the only
// function that changes which key a domain is sealed to.
//
// The previous effective manifest is demoted, not deleted: it stays for
// diagnostics, and its id is what a delayed message in the queue still names.
// Observations are reconciled against the new id in the same step, so a peer is
// never left describing a manifest it no longer has.
func Install(p *mailkey.Peer, r mailkey.Result, now time.Time) {
	rec := mailkey.ManifestRecord{
		ManifestID:     r.ManifestID,
		CanonicalBytes: append([]byte(nil), r.Raw...),
		Kid:            r.Manifest.Key.Kid,
		IssuedAt:       r.Manifest.IssuedAt,
		ExpiresAt:      r.Manifest.ExpiresAt,
		FetchedAt:      r.FetchedAt,
		AuthorityHost:  r.TLSHost,
		TLSVerified:    true,
		Status:         mailkey.ManifestEffective,
	}
	if prev := p.Effective; prev != nil {
		if prev.ManifestID == r.ManifestID {
			// The same manifest re-fetched: a confirmation, not a rotation.
			// Keep the history untouched and only refresh the timestamps.
			rec.FetchedAt = r.FetchedAt
		} else {
			// A different manifest: the authority rotated (or changed policy).
			// Two changes inside the instability window is not something to
			// resolve — it is something to report.
			if !prev.FetchedAt.IsZero() && r.FetchedAt.Sub(prev.FetchedAt) < instabilityWindow && rotatedBack(p, r.ManifestID) {
				p.AuthorityUnstable = true
			}
			demoted := *prev
			demoted.Status = mailkey.ManifestHistorical
			p.History = append([]mailkey.ManifestRecord{demoted}, p.History...)
			if len(p.History) > HistoryLimit {
				p.History = p.History[:HistoryLimit]
			}
		}
	}
	p.Effective = &rec
	p.LastVerifiedAt = r.FetchedAt
	p.LastError = ""
	p.NextRefreshAt = refreshAt(r)
	if p.Policy != mailkey.PolicyDisabled {
		p.State = mailkey.StateActive
	}
	Reconcile(p, now)
}

// rotatedBack reports whether this manifest id was already seen in the peer's
// recent history — the A/B/A pattern that marks an unstable authority, as
// opposed to a monotone sequence of new manifests.
func rotatedBack(p *mailkey.Peer, id mailkey.ManifestID) bool {
	for _, h := range p.History {
		if h.ManifestID == id {
			return true
		}
	}
	return false
}

// refreshAt is when a manifest should be refreshed: RefreshBefore ahead of the
// cache expiry, and never in the past.
func refreshAt(r mailkey.Result) time.Time {
	expiry := r.ExpiresAt
	if expiry.IsZero() {
		expiry = r.Manifest.ExpiresAt
	}
	at := expiry.Add(-RefreshBefore)
	if at.Before(r.FetchedAt) {
		// A short-lived manifest: refresh halfway through its life rather than
		// immediately, so a 1-hour manifest does not cause a fetch per send.
		at = r.FetchedAt.Add(expiry.Sub(r.FetchedAt) / 2)
	}
	return at
}

// Observe records an untrusted sighting. Observations coalesce per source: the
// newest sighting from DNS replaces the previous DNS one, so a mail flood or a
// polled record cannot grow the record without bound.
func Observe(p *mailkey.Peer, o mailkey.Observation, now time.Time) {
	if o.ObservedAt.IsZero() {
		o.ObservedAt = now
	}
	o.Status = classify(p, o)
	replaced := false
	for i := range p.Observations {
		if p.Observations[i].Source == o.Source {
			p.Observations[i] = o
			replaced = true
			break
		}
	}
	if !replaced {
		p.Observations = append(p.Observations, o)
	}
	// DNS may legitimately present several different valid records at once
	// (mid-rotation); that is inconsistency to record, never a choice to make.
	if p.State == "" {
		p.State = mailkey.StateDiscovered
	}
}

// classify compares one observation to the effective manifest.
func classify(p *mailkey.Peer, o mailkey.Observation) mailkey.ObservationStatus {
	if o.Status == mailkey.ObservationMalformed || o.Status == mailkey.ObservationInconsistent {
		return o.Status // the caller already knows the parse failed
	}
	if !o.HasID {
		// A capability claim with no id: nothing to compare, and nothing stale
		// about it either.
		return mailkey.ObservationPending
	}
	if p.Effective == nil {
		return mailkey.ObservationPending
	}
	if p.Effective.ManifestID == o.ManifestID {
		return mailkey.ObservationConfirmed
	}
	return mailkey.ObservationStale
}

// Reconcile re-classifies every observation against the current effective
// manifest and recomputes the peer's state. Called after an install, and by a
// Store that wants a peer's state to be current when it is read back.
func Reconcile(p *mailkey.Peer, now time.Time) {
	for i := range p.Observations {
		p.Observations[i].Status = classify(p, p.Observations[i])
	}
	if p.Policy == mailkey.PolicyDisabled {
		p.State = mailkey.StateDisabled
		return
	}
	switch {
	case p.Effective == nil && p.LastError != "":
		p.State = mailkey.StateUnavailable
	case p.Effective == nil:
		p.State = mailkey.StateDiscovered
	case !p.Effective.ExpiresAt.After(now):
		p.State = mailkey.StateExpired
	default:
		p.State = mailkey.StateActive
	}
}

// Fail records a resolution failure WITHOUT disturbing a manifest that is still
// valid. This is the downgrade-protection rule in code: a peer that validated
// once keeps its key through a transient outage, so a temporary DNS or HTTPS
// failure can never quietly turn into plaintext delivery.
func Fail(p *mailkey.Peer, err error, now time.Time) {
	if err != nil {
		p.LastError = err.Error()
	}
	// A definitive absence is worth remembering as such: the domain answered,
	// and said it publishes nothing.
	Reconcile(p, now)
}

// Usable reports whether the peer has a manifest the outbound path may seal
// with, and returns it. A manifest past its cache expiry is not usable even
// though it is still stored — the stored copy exists for diagnostics and for
// naming what an already-queued message was sealed to.
func Usable(p *mailkey.Peer, now time.Time) (mailkey.ManifestRecord, bool) {
	if p == nil || p.Effective == nil || p.Policy == mailkey.PolicyDisabled {
		return mailkey.ManifestRecord{}, false
	}
	if !p.Effective.ExpiresAt.After(now) {
		return mailkey.ManifestRecord{}, false
	}
	return *p.Effective, true
}

// NeedsRefresh reports whether resolution should run for this peer, and why.
//
// The triggers are exactly the spec's: nothing cached, expiry near or past, or
// an observation reporting an id that differs from the effective one. The last
// is why observations matter at all — they cannot install a key, but they can
// tell us our cache is behind.
func NeedsRefresh(p *mailkey.Peer, now time.Time) (bool, string) {
	if p == nil {
		return true, "unknown peer"
	}
	if p.Policy == mailkey.PolicyDisabled {
		return false, "disabled"
	}
	if p.Effective == nil {
		return true, "no effective manifest"
	}
	if !p.Effective.ExpiresAt.After(now) {
		return true, "manifest expired"
	}
	if !p.NextRefreshAt.IsZero() && !p.NextRefreshAt.After(now) {
		return true, "manifest nearing expiry"
	}
	for _, o := range p.Observations {
		if o.HasID && o.ManifestID != p.Effective.ManifestID {
			return true, "observed manifest id differs (" + string(o.Source) + ")"
		}
	}
	return false, ""
}

// Forget clears cached manifests and observations. It is not a blocklist: the
// peer keeps existing only as far as its administrative policy, and the domain
// may be rediscovered by the next observation. Queued messages are unaffected —
// they carry the kid and manifest id they were sealed with.
func Forget(p *mailkey.Peer) {
	p.Effective = nil
	p.History = nil
	p.Observations = nil
	p.LastVerifiedAt = time.Time{}
	p.NextRefreshAt = time.Time{}
	p.LastError = ""
	p.AuthorityUnstable = false
	if p.Policy == mailkey.PolicyDisabled {
		p.State = mailkey.StateDisabled
		return
	}
	p.State = mailkey.StateDiscovered
}
