/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package wellknown_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/wellknown"
)

// fakePublisher publishes for a fixed set of domains.
type fakePublisher struct {
	raw     map[string][]byte
	expires time.Time
	asked   []string
}

func (f *fakePublisher) CurrentManifest(domain string) ([]byte, mailkey.ManifestID, time.Time, bool) {
	f.asked = append(f.asked, domain)
	raw, ok := f.raw[domain]
	if !ok {
		return nil, mailkey.ManifestID{}, time.Time{}, false
	}
	return raw, manifest.ManifestIDOf(raw), f.expires, true
}

func (f *fakePublisher) ManifestIDFor(domain string) (mailkey.ManifestID, bool) {
	_, id, _, ok := f.CurrentManifest(domain)
	return id, ok
}

func newFixture(t *testing.T, domains ...string) (*wellknown.Handler, *fakePublisher) {
	t.Helper()
	now := time.Unix(1750000000, 0).UTC()
	pub := &fakePublisher{raw: map[string][]byte{}, expires: now.Add(7 * 24 * time.Hour)}
	for _, d := range domains {
		m, err := manifest.New(d, now, pub.expires, mailkey.AlgX25519, mailkey.EncAES256GCM, testKey(d))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := manifest.Pack(m)
		if err != nil {
			t.Fatal(err)
		}
		pub.raw[d] = raw
	}
	h := wellknown.NewHandler(pub)
	h.Now = func() time.Time { return now }
	return h, pub
}

// testKey is a distinct 32-byte public key per domain.
func testKey(domain string) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(len(domain) + i)
	}
	return k
}

func get(h http.Handler, method, host string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, mailkey.WellKnownPath, nil)
	r.Host = host
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestServesTheAuthorityDomain: a request to mail.<domain> answers with that
// domain's manifest, byte for byte, tagged by its own id.
func TestServesTheAuthorityDomain(t *testing.T) {
	h, pub := newFixture(t, "example.com")

	w := get(h, http.MethodGet, "mail.example.com", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	want := pub.raw["example.com"]
	if got := w.Body.Bytes(); string(got) != string(want) {
		t.Fatal("body is not the published bytes")
	}
	if ct := w.Header().Get("Content-Type"); ct != mailkey.MediaType {
		t.Fatalf("content type %q", ct)
	}
	if etag := w.Header().Get("ETag"); etag != `"`+manifest.EncodeID(manifest.ManifestIDOf(want))+`"` {
		t.Fatalf("etag %q is not the manifest id", etag)
	}
	if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(len(want)) {
		t.Fatalf("content-length %q for %d bytes", cl, len(want))
	}
	// The bytes served must still validate as canonical MKDP1 for that domain —
	// the endpoint is not allowed to reshape them on the way out.
	if _, err := manifest.ParseCanonical(w.Body.Bytes(), "example.com"); err != nil {
		t.Fatalf("served bytes do not validate: %v", err)
	}
}

// TestAnswersOnlyForPublishedDomains is the property that makes the host header
// harmless: it selects a candidate, never the answer.
func TestAnswersOnlyForPublishedDomains(t *testing.T) {
	h, _ := newFixture(t, "example.com")

	for _, host := range []string{
		"mail.other.com",             // a domain we do not host
		"other.com",                  //   "
		"mail.example.com.evil.test", // our name as a prefix of theirs
		"localhost", "127.0.0.1", "",
		"mail.example.com:8443", // arrived somewhere that is not the authority port
	} {
		if w := get(h, http.MethodGet, host, nil); w.Code != http.StatusNotFound {
			t.Errorf("host %q: status %d, want 404", host, w.Code)
		}
	}
	// A miss must not be cacheable: the domain may get a key a minute later.
	w := get(h, http.MethodGet, "mail.other.com", nil)
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("404 cache-control %q", cc)
	}
}

// TestBareHostAndAuthorityBothResolve covers the shared-address deployment: one
// server answering on both its webmail name and the mail authority.
func TestBareHostAndAuthorityBothResolve(t *testing.T) {
	h, pub := newFixture(t, "example.com")
	for _, host := range []string{"mail.example.com", "example.com", "MAIL.Example.com", "mail.example.com:443"} {
		w := get(h, http.MethodGet, host, nil)
		if w.Code != http.StatusOK || string(w.Body.Bytes()) != string(pub.raw["example.com"]) {
			t.Errorf("host %q: status %d", host, w.Code)
		}
	}
	// A domain literally named mail.<something> is served as itself, and the
	// protocol's reading is tried first.
	h2, pub2 := newFixture(t, "example.com", "mail.example.com")
	w := get(h2, http.MethodGet, "mail.example.com", nil)
	if string(w.Body.Bytes()) != string(pub2.raw["example.com"]) {
		t.Fatal("the authority reading must win when both are hosted")
	}
	h3, pub3 := newFixture(t, "mail.example.com")
	w = get(h3, http.MethodGet, "mail.example.com", nil)
	if string(w.Body.Bytes()) != string(pub3.raw["mail.example.com"]) {
		t.Fatal("a domain named mail.<x> must be served as itself when it is the only match")
	}
}

// TestCachingIsBoundedByValidity: a cache must never be told it may hold a
// manifest past the point the receiver promised to keep the key openable.
func TestCachingIsBoundedByValidity(t *testing.T) {
	h, pub := newFixture(t, "example.com")

	// Far from expiry, the cache bound applies.
	w := get(h, http.MethodGet, "mail.example.com", nil)
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age="+strconv.Itoa(int(wellknown.MaxCacheAge.Seconds())) {
		t.Fatalf("cache-control %q", cc)
	}
	// Close to expiry, the remaining validity applies instead.
	pub.expires = h.Now().Add(90 * time.Second)
	w = get(h, http.MethodGet, "mail.example.com", nil)
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=90" {
		t.Fatalf("near expiry: cache-control %q", cc)
	}
	// Past expiry it is not cacheable at all (and must not go negative).
	pub.expires = h.Now().Add(-time.Hour)
	w = get(h, http.MethodGet, "mail.example.com", nil)
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=0" {
		t.Fatalf("expired: cache-control %q", cc)
	}
}

// TestConditionalAndHead are the two request shapes a well-behaved fetcher uses
// to avoid moving bytes it already has.
func TestConditionalAndHead(t *testing.T) {
	h, pub := newFixture(t, "example.com")
	etag := `"` + manifest.EncodeID(manifest.ManifestIDOf(pub.raw["example.com"])) + `"`

	w := get(h, http.MethodGet, "mail.example.com", map[string]string{"If-None-Match": etag})
	if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("matching etag: status %d, %d bytes", w.Code, w.Body.Len())
	}
	if w.Header().Get("ETag") != etag || w.Header().Get("Cache-Control") == "" {
		t.Fatal("a 304 must still carry the validator and freshness")
	}
	// A list, and the wildcard, both match; a different tag does not.
	for _, v := range []string{`"other", ` + etag, "*", etag + ` , "x"`} {
		if w := get(h, http.MethodGet, "mail.example.com", map[string]string{"If-None-Match": v}); w.Code != http.StatusNotModified {
			t.Errorf("If-None-Match %q: status %d", v, w.Code)
		}
	}
	for _, v := range []string{`"nope"`, `W/` + etag, ""} {
		if w := get(h, http.MethodGet, "mail.example.com", map[string]string{"If-None-Match": v}); w.Code != http.StatusOK {
			t.Errorf("If-None-Match %q: status %d, want 200", v, w.Code)
		}
	}
	// HEAD reports the full metadata and no body.
	w = get(h, http.MethodHead, "mail.example.com", nil)
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD: status %d, %d bytes", w.Code, w.Body.Len())
	}
	if w.Header().Get("Content-Length") != strconv.Itoa(len(pub.raw["example.com"])) {
		t.Fatal("HEAD must report the real length")
	}
}

// TestOnlyReadMethods: the endpoint publishes, it never accepts.
func TestOnlyReadMethods(t *testing.T) {
	h, _ := newFixture(t, "example.com")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := get(h, m, "mail.example.com", nil)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d", m, w.Code)
		}
		if w.Header().Get("Allow") == "" {
			t.Errorf("%s: no Allow header", m)
		}
	}
}

// TestNoPublisherIsNotACrash: a server wired without a publisher answers 404,
// because a nil dependency must not be a panic on a public port.
func TestNoPublisherIsNotACrash(t *testing.T) {
	h := &wellknown.Handler{}
	if w := get(h, http.MethodGet, "mail.example.com", nil); w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}
