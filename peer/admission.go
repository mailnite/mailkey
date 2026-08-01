/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer

import (
	"sync"
	"time"

	"github.com/mailnite/mailkey"
)

/*
Admission control for untrusted observations.

The bounded queue in service.go protects the NETWORK side of header discovery:
a flood of Mail-Key headers cannot spawn unbounded outbound fetches. It does not
protect the STORAGE side, and that was the hole. PutObservation creates a peer
record for a domain we have never heard of, so anyone able to send us mail could
write one durable record per unique domain in the header — memory in the lock
table, keys in the peer book, work for every operation that enumerates peers.
Nothing in the message has to be true for this to happen: the header is an
unauthenticated hint from a stranger, which is exactly why the spec says a
receiver SHOULD bound and rate-limit header-triggered discovery (§3).

Two limits, because there are two distinct costs:

  - REPEATS are coalesced. The tenth message this hour advertising the same id
    for the same domain tells us nothing the first did not, so it is dropped
    before it reaches storage. This is what collapses the ordinary flood — one
    sender, many messages — into a single write, and it is keyed on the id so a
    ROTATION still gets through immediately. A rotation is the one observation
    that matters, and rate-limiting it would be rate-limiting the protocol.

  - NEW PEERS are quota'd. Repeats coalesce a flood from one domain; a flood
    from a million unique domains needs a different answer, because each one is
    a first sighting. A token bucket bounds how fast unknown domains may become
    durable records, so the worst case is a known number of rows per hour
    instead of one per message.

Refusing is always safe, which is what makes this the right place to be strict:
a dropped hint costs nothing. The peer is discovered by the next message after
the bucket refills, or — the path that actually matters — resolved synchronously
the moment we send mail TO that domain, which is the only time we need its key.

The tracking map is itself bounded state, so it is swept and hard-capped: an
admission control that grows without limit is the bug it was meant to fix.
*/

// admissionDefaults, exported through Options so an operator can tune them.
const (
	defaultObserveInterval = 10 * time.Minute
	defaultNewPeerBurst    = 256
	defaultNewPeerRefill   = time.Hour / 256 // 256 new peers per hour, sustained
	maxTrackedDomains      = 8192
)

// admission decides whether an untrusted observation is allowed to reach
// storage. The zero value is not usable — build it with newAdmission.
type admission struct {
	mu sync.Mutex

	// interval is how long an identical observation is considered already
	// recorded.
	interval time.Duration

	// seen maps domain -> the last decision made for it. A domain that was
	// REFUSED is remembered here too: that is the negative cache, and it is
	// what keeps a flood of unknown domains from re-reading the peer book once
	// per message.
	seen map[string]decision

	// The new-peer bucket. tokens is fractional in the sense that refill is
	// computed from elapsed time rather than ticked.
	tokens     float64
	burst      float64
	refillEach time.Duration
	lastRefill time.Time
}

// decision is what we last did about a domain, and when.
type decision struct {
	at time.Time
	// id is the manifest id that was observed, so a DIFFERENT id is treated as
	// news rather than as a repeat.
	id     mailkey.ManifestID
	hasID  bool
	source mailkey.Source
}

func newAdmission(interval time.Duration, burst int, refillEach time.Duration, now time.Time) *admission {
	if interval <= 0 {
		interval = defaultObserveInterval
	}
	if burst <= 0 {
		burst = defaultNewPeerBurst
	}
	if refillEach <= 0 {
		refillEach = defaultNewPeerRefill
	}
	return &admission{
		interval:   interval,
		seen:       map[string]decision{},
		tokens:     float64(burst),
		burst:      float64(burst),
		refillEach: refillEach,
		lastRefill: now,
	}
}

/*
allowObservation reports whether an observation about domain should reach
storage, and records the decision.

The key is (domain, source, id): a header and a DNS record about the same domain
are different evidence, and a changed id is different evidence again. Anything
else within the interval is the same hint arriving twice.
*/
func (a *admission) allowObservation(domain string, source mailkey.Source, id mailkey.ManifestID, hasID bool, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if d, ok := a.seen[domain]; ok && d.source == source && d.hasID == hasID && d.id == id {
		if now.Sub(d.at) < a.interval {
			return false
		}
	}
	a.sweepLocked(now)
	a.seen[domain] = decision{at: now, id: id, hasID: hasID, source: source}
	return true
}

/*
allowNewPeer takes a token for a domain that has no peer record yet.

Only first sightings spend one. An observation about a domain we already know is
an update to a row that exists, so it costs no new storage and is not what this
bucket is for.
*/
func (a *admission) allowNewPeer(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if elapsed := now.Sub(a.lastRefill); elapsed > 0 {
		a.tokens += float64(elapsed) / float64(a.refillEach)
		if a.tokens > a.burst {
			a.tokens = a.burst
		}
		a.lastRefill = now
	}
	if a.tokens < 1 {
		return false
	}
	a.tokens--
	return true
}

// forget drops a domain's memory, so an administrative action (AddPeer,
// Refresh, Forget) is never answered with a cached decision about the domain it
// just changed.
func (a *admission) forget(domain string) {
	a.mu.Lock()
	delete(a.seen, domain)
	a.mu.Unlock()
}

// sweepLocked keeps the tracking map bounded. Entries older than the interval
// have no effect on any future decision, so they go first; if the map is still
// at the cap after that, the oldest quarter is evicted. Evicting only makes us
// re-decide a domain sooner, never wrong.
func (a *admission) sweepLocked(now time.Time) {
	if len(a.seen) < maxTrackedDomains {
		return
	}
	for d, v := range a.seen {
		if now.Sub(v.at) >= a.interval {
			delete(a.seen, d)
		}
	}
	if len(a.seen) < maxTrackedDomains {
		return
	}
	// Still full: evict the oldest quarter. A partial sort would be exact; a
	// threshold pass is O(n) and close enough for a cache whose only job is to
	// avoid repeated work.
	var oldest, newest time.Time
	for _, v := range a.seen {
		if oldest.IsZero() || v.at.Before(oldest) {
			oldest = v.at
		}
		if v.at.After(newest) {
			newest = v.at
		}
	}
	cutoff := oldest.Add(newest.Sub(oldest) / 4)
	for d, v := range a.seen {
		if !v.at.After(cutoff) {
			delete(a.seen, d)
		}
	}
}
