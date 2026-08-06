/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package wellknown_test

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/wellknown"
)

// fakePublisher publishes for a fixed set of domains. signer, when set, signs
// each publication so the handler's proof plumbing is exercised.
type fakePublisher struct {
	raw     map[string][]byte
	expires time.Time
	asked   []string
	signer  ed25519.PrivateKey
}

func (f *fakePublisher) CurrentManifest(domain string) (mailkey.Publication, bool) {
	f.asked = append(f.asked, domain)
	raw, ok := f.raw[domain]
	if !ok {
		return mailkey.Publication{}, false
	}
	out := mailkey.Publication{Raw: raw, ID: manifest.ManifestIDOf(raw), ExpiresAt: f.expires}
	if f.signer != nil {
		pk := f.signer.Public().(ed25519.PublicKey)
		fp, err := identity.FingerprintOf(domain, pk)
		if err != nil {
			return mailkey.Publication{}, false
		}
		sig, err := identity.SignManifest(f.signer, domain, raw)
		if err != nil {
			return mailkey.Publication{}, false
		}
		out.Proof = &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}
	}
	return out, true
}

func (f *fakePublisher) ManifestIDFor(domain string) (mailkey.ManifestID, bool) {
	pub, ok := f.CurrentManifest(domain)
	return pub.ID, ok
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

/*
TestMediaTypeIsGenericMessagePack pins the content type, because it is a wire
contract and not a label: a peer that refuses the type never reaches the bytes.

The generic type is deliberate. A manifest IS canonical MessagePack, nothing
about reading one depends on knowing who wrote the schema, and a vendor tree
would both imply the format belongs to one implementation and make ordinary
tooling treat the response as exotic.
*/
func TestMediaTypeIsGenericMessagePack(t *testing.T) {
	if mailkey.MediaType != "application/msgpack" {
		t.Fatalf("media type = %q; changing it is a protocol change", mailkey.MediaType)
	}
	h, _ := newFixture(t, "example.com")
	w := get(h, http.MethodGet, "mail.example.com", nil)
	if got := w.Header().Get("Content-Type"); got != "application/msgpack" {
		t.Fatalf("served content type = %q", got)
	}
	// Not a vendor tree, and not a type that invites sniffing.
	if strings.Contains(w.Header().Get("Content-Type"), "vnd.") {
		t.Fatal("the discovery response must not use a vendor media type")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("a binary response must be served nosniff")
	}
}

/*
TestProofFieldsTravelWithTheBody: a signed publication puts its three proof
fields on the response, and they are the ones that authenticate THAT body.

The pairing is the whole property. A handler that looked up the manifest and the
current identity separately could serve one build's bytes beside another's
signature, and since the proof is detached there is nothing in the body to
notice — every correspondent would simply see a verification failure and, for a
pinned domain, read it as an attack.
*/
func TestProofFieldsTravelWithTheBody(t *testing.T) {
	h, pub := newFixture(t, "x.test")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub.signer = priv

	w := get(h, "GET", "mail.x.test", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	proof, found, err := identity.ReadProof(w.Header())
	if err != nil || !found {
		t.Fatalf("proof fields: found=%v err=%v", found, err)
	}
	if err := identity.Check(proof, "x.test", w.Body.Bytes()); err != nil {
		t.Fatalf("the served proof does not authenticate the served body: %v", err)
	}
	// The signer names the domain the request was FOR, not the host it arrived
	// on: a fingerprint computed over "mail.x.test" would never match the pin a
	// correspondent holds for x.test.
	if _, err := identity.FingerprintOf("mail.x.test", proof.PublicKey); err == nil {
		if err := identity.Check(proof, "mail.x.test", w.Body.Bytes()); err == nil {
			t.Fatal("the proof verified under the authority host rather than the domain")
		}
	}
}

// TestUnsignedPublicationCarriesNoProofFields: a domain without an identity key
// serves a manifest and NO proof fields. Not a subset, not empty values — a
// partial proof is malformed, and a client is required to treat it as an attack.
func TestUnsignedPublicationCarriesNoProofFields(t *testing.T) {
	h, _ := newFixture(t, "x.test")
	w := get(h, "GET", "mail.x.test", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for _, name := range []string{mailkey.HeaderIdentity, mailkey.HeaderSigner, mailkey.HeaderSignature} {
		if v := w.Header().Get(name); v != "" {
			t.Fatalf("unsigned publication set %s = %q", name, v)
		}
	}
	if _, found, err := identity.ReadProof(w.Header()); err != nil || found {
		t.Fatalf("an unsigned response must read as absent, not malformed: found=%v err=%v", found, err)
	}
}

// TestNotModifiedKeepsItsOwnProof: a 304 must not let a cached body become
// associated with another response's proof. The etag IS the hash of the body, so
// re-sending this publication's own proof alongside its own validator is the only
// pairing a client can end up with.
func TestNotModifiedKeepsItsOwnProof(t *testing.T) {
	h, pub := newFixture(t, "x.test")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub.signer = priv

	first := get(h, "GET", "mail.x.test", nil)
	etag := first.Header().Get("ETag")
	body := first.Body.Bytes()

	second := get(h, "GET", "mail.x.test", map[string]string{"If-None-Match": etag})
	if second.Code != http.StatusNotModified {
		t.Fatalf("status %d, want 304", second.Code)
	}
	proof, found, err := identity.ReadProof(second.Header())
	if err != nil || !found {
		t.Fatalf("a 304 must still carry the proof for the body it validates: found=%v err=%v", found, err)
	}
	if err := identity.Check(proof, "x.test", body); err != nil {
		t.Fatalf("the 304's proof does not authenticate the cached body: %v", err)
	}
}

/*
TestSubjectQuerySelectsTheDomain pins the serving half of delegated authority:
ONE authority host serves MANY domains, and ?d= says which.

Four properties, each load-bearing:

  - a hosted subject is served regardless of the Host header — that is what
    makes mail.{primary} the authority for customer domains;
  - an UNHOSTED subject 404s exactly like any stranger, so a request can name
    a domain but never enumerate what this server hosts (the customer list
    stays private);
  - a malformed ?d= is refused rather than silently falling back to the Host:
    a malformed subject is a malformed request, not a request for something
    else;
  - without ?d= the Host still decides, so old resolvers keep working
    unchanged.
*/
func TestSubjectQuerySelectsTheDomain(t *testing.T) {
	const authorityDomain = "primary.example"
	const customer = "customer.example"
	h, pub := newFixture(t, authorityDomain, customer)

	get := func(host, query string) *httptest.ResponseRecorder {
		url := "/.well-known/mail-key"
		if query != "" {
			url += "?d=" + query
		}
		r := httptest.NewRequest(http.MethodGet, url, nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// The customer's manifest, served by the PRIMARY's host.
	w := get("mail."+authorityDomain, customer)
	if w.Code != http.StatusOK {
		t.Fatalf("delegated subject: %d", w.Code)
	}
	if !bytes.Equal(w.Body.Bytes(), pub.raw[customer]) {
		t.Fatal("?d= must select the SUBJECT's manifest, not the host's")
	}

	// The host's own domain still works through the same query form.
	if w := get("mail."+authorityDomain, authorityDomain); w.Code != http.StatusOK ||
		!bytes.Equal(w.Body.Bytes(), pub.raw[authorityDomain]) {
		t.Fatalf("self subject via ?d=: %d", w.Code)
	}

	// A domain this server does not host: the ordinary 404, no hint that it
	// hosts anything else.
	if w := get("mail."+authorityDomain, "stranger.example"); w.Code != http.StatusNotFound {
		t.Fatalf("unhosted subject must 404, got %d", w.Code)
	}

	// Malformed subjects are refused outright — never a fallback to the Host.
	for _, bad := range []string{"https://evil.example", "evil.example:443", "127.0.0.1", "*.example"} {
		if w := get("mail."+authorityDomain, url.QueryEscape(bad)); w.Code != http.StatusNotFound {
			t.Fatalf("d=%q must be refused, got %d", bad, w.Code)
		}
	}

	// No ?d= at all: the Host decides, exactly as before delegation existed.
	if w := get("mail."+authorityDomain, ""); w.Code != http.StatusOK ||
		!bytes.Equal(w.Body.Bytes(), pub.raw[authorityDomain]) {
		t.Fatalf("host-derived lookup must still work: %d", w.Code)
	}
}
