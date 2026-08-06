/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package wellknown serves the publishing half of MKDP1: the single authority
endpoint at https://mail.<domain>/.well-known/mail-key.

The endpoint is the whole trust anchor of the protocol. A client learns a
domain's key from exactly one place — this URL, over TLS that proves the host
name — and treats DNS records and mail headers only as hints that something may
have changed. So what this package must get right is narrow but load-bearing:
answer for the domain the request was actually addressed to, serve the canonical
bytes verbatim, and describe their validity honestly enough that caches cannot
outlive it.

It deliberately does NOT decide what to publish. It takes a mailkey.Publisher and
serves what that returns, so the decisions with consequences — which domains are
ours, whether a key's private half exists, when a manifest expires — stay with
the server that owns the keys.
*/
package wellknown

import (
	"crypto/sha256"
	"net/http"
	"strconv"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/manifest"
)

// MaxCacheAge bounds how long an intermediary HTTP cache may hold a response,
// independently of how long the manifest itself declares validity.
//
// The two are different clocks and conflating them costs rotation speed. A
// manifest's expires_at is a promise to SENDERS: the receiver will keep the key
// openable at least that long, which is why it can safely be days. An HTTP
// cache's max-age only decides how stale a copy some proxy may hand out, and a
// long one means a rotation stays invisible to that proxy for days after the
// receiver has already published the new key. An hour spares the authority
// essentially all repeat load while keeping rotations promptly visible.
const MaxCacheAge = time.Hour

/*
Handler answers MKDP1 discovery requests from a Publisher.

Two properties are worth stating because they are easy to get wrong in the
opposite direction:

It does not require TLS on the request. The protocol requires the CLIENT to fetch
over HTTPS and to verify the authority host, and the client is where that has to
be enforced — a server checking r.TLS proves nothing to anyone and breaks the
common deployment where a load balancer or Kubernetes ingress terminates TLS and
forwards plaintext. A manifest is public data; the guarantee is that the client
got it over a verified connection, not that the origin socket was encrypted.

It answers only for domains the Publisher claims. The host header selects a
CANDIDATE, never the answer: an unknown or foreign host produces 404 because the
Publisher declines it, so no request can make a server speak for a domain it does
not host.
*/
type Handler struct {
	// Publisher supplies each domain's canonical manifest bytes.
	Publisher mailkey.Publisher
	// MaxAge overrides MaxCacheAge when set.
	MaxAge time.Duration
	// Now is the clock, for tests.
	Now func() time.Time
}

// NewHandler builds the endpoint handler for a publisher.
func NewHandler(p mailkey.Publisher) *Handler { return &Handler{Publisher: p} }

var _ http.Handler = (*Handler)(nil)

func (t *Handler) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Handler) maxAge() time.Duration {
	if t.MaxAge > 0 {
		return t.MaxAge
	}
	return MaxCacheAge
}

func (t *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if t.Publisher == nil {
		t.miss(w)
		return
	}
	if r.URL.Path == identity.ResourcePath {
		t.serveIdentity(w, r)
		return
	}
	pub, ok := t.lookup(r)
	if !ok {
		t.miss(w)
		return
	}

	etag := `"` + manifest.EncodeID(pub.ID) + `"`
	// A strong validator is honest here in a way it usually is not: the id IS the
	// hash of the bytes being served, so equal etags cannot mean different bodies.
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(t.cacheSeconds(pub.ExpiresAt).Seconds())))
	h.Set("Content-Type", mailkey.MediaType)
	h.Set("X-Content-Type-Options", "nosniff")
	// The proof comes from the SAME snapshot as the body, which is the whole
	// point of the snapshot: a proof is only ever valid against the exact bytes
	// it signed, so a handler that fetched the two separately could pair one
	// build's body with another's signature and every correspondent would see a
	// verification failure.
	identity.WriteProof(h, pub.Proof)

	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		// The proof fields stay set on the 304. A cached body and a proof from a
		// different response must never become associated, and since the etag IS
		// the hash of the body, re-sending this snapshot's proof alongside its own
		// validator is the only pairing that can result.
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(pub.Raw)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pub.Raw)
}

/*
lookup decides WHICH domain's manifest this request is asking for.

?d= names the subject explicitly, which is what lets one authority host serve
many domains (delegated authority). It is a request for a NAMED domain, never
a listing: the publisher answers only for what it actually hosts, so an
unhosted (or hostile) d= gets the same 404 as any other stranger, and no
request can enumerate what this server hosts.

The subject is normalized before it reaches the publisher — one domain must
not be answerable under two spellings — and an unparseable d= is refused
rather than quietly falling back to the Host, because a malformed subject is
a malformed request, not a request for something else.

Without ?d= the host decides, exactly as before: this endpoint answers old
resolvers (and hand-typed URLs) unchanged, and for a self-hosted domain that
is the same manifest either way.
*/
func (t *Handler) lookup(r *http.Request) (mailkey.Publication, bool) {
	if raw := r.URL.Query().Get(mailkey.SubjectQueryParam); raw != "" {
		d, err := discovery.Normalize(raw)
		if err != nil {
			return mailkey.Publication{}, false
		}
		pub, ok := t.Publisher.CurrentManifest(d)
		if !ok || len(pub.Raw) == 0 {
			return mailkey.Publication{}, false
		}
		return pub, true
	}
	for _, d := range discovery.DomainCandidatesOf(r.Host) {
		if pub, ok := t.Publisher.CurrentManifest(d); ok && len(pub.Raw) > 0 {
			return pub, true
		}
	}
	return mailkey.Publication{}, false
}

// cacheSeconds is the shorter of "until this manifest expires" and the cache
// bound. Never negative: an expired manifest should not be served at all, and if
// one is, it must at least not be cacheable.
func (t *Handler) cacheSeconds(expires time.Time) time.Duration {
	age := t.maxAge()
	if !expires.IsZero() {
		if left := expires.Sub(t.now()).Truncate(time.Second); left < age {
			age = left
		}
	}
	if age < 0 {
		return 0
	}
	return age
}

// miss is the answer for a domain this server does not publish for. It is
// explicitly not cacheable: a domain may be added, or its first key generated,
// at any moment, and a cached 404 would keep senders in cleartext long after
// that.
func (t *Handler) miss(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "no MKDP1 manifest is published for this host", http.StatusNotFound)
}

// etagMatches compares an If-None-Match list against our tag. Only exact
// (strong) matches count, plus "*"; a weak validator is not a match, since the
// bytes are the identifier and there is no weaker equivalence to appeal to.
func etagMatches(list, etag string) bool {
	for len(list) > 0 {
		// Split on commas, trimming space and any trailing separator.
		i := 0
		for i < len(list) && list[i] != ',' {
			i++
		}
		candidate := trimSpace(list[:i])
		if candidate == "*" || candidate == etag {
			return true
		}
		if i >= len(list) {
			break
		}
		list = list[i+1:]
	}
	return false
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

/*
serveIdentity answers the §4.2 identity resource: the active signing identity
and the rotation chain a pinned correspondent walks.

Served only when the Publisher also publishes identities; otherwise 404, which
is byte-for-byte what a server that never signed answers — so "this domain does
not sign" and "this software predates signing" stay indistinguishable, and the
endpoint is not a version fingerprint.

Moderate caching with a strong ETag, exactly as the spec asks: the document
changes only on rotation, and the hash of its bytes is an honest validator for
the same reason the manifest id is.
*/
func (t *Handler) serveIdentity(w http.ResponseWriter, r *http.Request) {
	ip, ok := t.Publisher.(mailkey.IdentityPublisher)
	if !ok {
		t.miss(w)
		return
	}
	var raw []byte
	found := false
	if q := r.URL.Query().Get(mailkey.SubjectQueryParam); q != "" {
		// Same subject rule as the manifest plane: an explicit ?d= is the
		// question, and only a hosted domain gets an answer — a named domain,
		// never a listing.
		d, derr := discovery.Normalize(q)
		if derr != nil {
			t.miss(w)
			return
		}
		if b, ok := ip.CurrentIdentityDoc(d); ok && len(b) > 0 {
			raw, found = b, true
		}
	} else {
		for _, d := range discovery.DomainCandidatesOf(r.Host) {
			if b, ok := ip.CurrentIdentityDoc(d); ok && len(b) > 0 {
				raw, found = b, true
				break
			}
		}
	}
	if !found {
		t.miss(w)
		return
	}
	sum := sha256.Sum256(raw)
	etag := `"` + manifest.EncodeID(sum) + `"`
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(t.maxAge().Seconds())))
	h.Set("Content-Type", mailkey.MediaType)
	h.Set("X-Content-Type-Options", "nosniff")
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(raw)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
