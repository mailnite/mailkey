/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package resolver_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/resolver"
)

const domain = "example.com"
const authority = "mail.example.com"

// authorityFixture is a stand-in MKDP1 authority: a real TLS server with a real
// chain, reached through the resolver's real dial path. Only name resolution is
// substituted (the one seam the package exposes), so the address policy, TLS
// validation, transfer limits and parsing under test are the production ones.
type authorityFixture struct {
	server  *httptest.Server
	ca      *testCA
	body    []byte
	status  int
	ctype   string
	header  map[string]string
	hits    atomic.Int64
	delay   time.Duration
	handler http.HandlerFunc
}

func newAuthority(t *testing.T, certNames ...string) *authorityFixture {
	t.Helper()
	ca := newTestCA(t)
	if len(certNames) == 0 {
		certNames = []string{authority}
	}
	f := &authorityFixture{ca: ca, status: http.StatusOK, ctype: mailkey.MediaType, header: map[string]string{}}
	f.body, _ = validManifest(t, domain, time.Now())
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		if f.handler != nil {
			f.handler(w, r)
			return
		}
		for k, v := range f.header {
			w.Header().Set(k, v)
		}
		if f.ctype != "" {
			w.Header().Set("Content-Type", f.ctype)
		}
		w.WriteHeader(f.status)
		_, _ = w.Write(f.body)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, certNames...)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.server = srv
	return f
}

// port returns the loopback port the fixture listens on.
func (f *authorityFixture) port() string {
	_, p, _ := net.SplitHostPort(f.server.Listener.Addr().String())
	return p
}

// lookupTo points every hostname at the fixture's loopback address. The dial
// path still applies the address policy to it, which is why the tests that use
// this must also opt into private targets — exactly as a split-DNS deployment
// would have to.
func (f *authorityFixture) lookupTo() resolver.LookupFunc {
	return func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
}

// newResolver builds a resolver aimed at the fixture. The fixture listens on an
// ephemeral loopback port, so the tests take the two deliberate opt-ins a
// split-DNS deployment would take — private targets and a port override — and
// nothing else: TLS validation, the address policy, the transfer limits and the
// parser are all the production ones.
func newResolver(t *testing.T, f *authorityFixture, mutate ...func(*resolver.Options)) *resolver.Resolver {
	t.Helper()
	opts := resolver.Options{
		Lookup:              f.lookupTo(),
		RootCAs:             f.ca.pool,
		AllowPrivateTargets: true,
		PortOverride:        f.port(),
		Timeout:             3 * time.Second,
	}
	for _, m := range mutate {
		m(&opts)
	}
	return resolver.New(opts)
}

// validManifest builds a canonical manifest for a domain, and returns its bytes
// and the key that opens messages sealed to it.
func validManifest(t *testing.T, d string, now time.Time) ([]byte, *ecdh.PrivateKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(d, now.Add(-time.Minute), now.Add(24*time.Hour),
		mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, priv
}

// TestResolveHappyPath: a correct authority yields a validated manifest whose
// identity is computed from the bytes that arrived.
func TestResolveHappyPath(t *testing.T) {
	f := newAuthority(t)
	r := newResolver(t, f)

	res, err := r.Resolve(context.Background(), "Example.COM.", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Domain != domain {
		t.Fatalf("domain = %q", res.Manifest.Domain)
	}
	if res.ManifestID != manifest.ManifestIDOf(f.body) {
		t.Fatal("the manifest id must be SHA-256 of the received bytes")
	}
	if string(res.Raw) != string(f.body) {
		t.Fatal("the raw bytes must be preserved verbatim")
	}
	if res.TLSHost != authority {
		t.Fatalf("TLSHost = %q, want %q", res.TLSHost, authority)
	}
	if !res.ExpiresAt.Equal(res.Manifest.ExpiresAt) {
		t.Fatal("with no Cache-Control the cache lifetime is the manifest's own")
	}
}

// TestTLSValidation: the chain and the hostname are both enforced. A wrong name
// or an unknown issuer is a TLS failure, distinguishable from a network one so a
// caller can treat interception differently from an outage.
func TestTLSValidation(t *testing.T) {
	// A certificate for the wrong host: valid chain, wrong name.
	wrong := newAuthority(t, "mail.attacker.example")
	r := newResolver(t, wrong)
	_, err := r.Resolve(context.Background(), domain, "")
	if err == nil {
		t.Fatal("a certificate for another host must be refused")
	}
	if c := mailkey.ClassOf(err); c != mailkey.FailureTLS {
		t.Fatalf("hostname mismatch should be class %q, got %q (%v)", mailkey.FailureTLS, c, err)
	}

	// An untrusted issuer: the system pool does not know our test CA.
	untrusted := newAuthority(t)
	r = newResolver(t, untrusted, func(o *resolver.Options) { o.RootCAs = x509.NewCertPool() })
	if _, err := r.Resolve(context.Background(), domain, ""); err == nil {
		t.Fatal("an untrusted issuer must be refused")
	} else if c := mailkey.ClassOf(err); c != mailkey.FailureTLS {
		t.Fatalf("unknown authority should be class %q, got %q (%v)", mailkey.FailureTLS, c, err)
	}

	// An expired certificate.
	ca := newTestCA(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.expiredLeaf(t, authority)}}
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	r = resolver.New(resolver.Options{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		RootCAs:             ca.pool,
		AllowPrivateTargets: true,
		PortOverride:        port,
		Timeout:             3 * time.Second,
	})
	if _, err := r.Resolve(context.Background(), domain, ""); err == nil {
		t.Fatal("an expired certificate must be refused")
	} else if c := mailkey.ClassOf(err); c != mailkey.FailureTLS {
		t.Fatalf("expired certificate should be class %q, got %q (%v)", mailkey.FailureTLS, c, err)
	}
}

// TestAddressPolicy is the SSRF test: with the default policy, an authority
// that resolves into a private range is never connected to — and the refusal is
// reported as OUR policy, not as a network error, so it is never mistaken for a
// transient outage worth retrying hard.
func TestAddressPolicy(t *testing.T) {
	f := newAuthority(t)
	for name, addr := range map[string]string{
		"loopback":      "127.0.0.1",
		"private 10":    "10.1.2.3",
		"private 192":   "192.168.1.1",
		"private 172":   "172.16.0.1",
		"link-local":    "169.254.1.1",
		"cgnat":         "100.64.1.1",
		"unspecified":   "0.0.0.0",
		"ipv6 loopback": "::1",
		"ipv6 ula":      "fd00::1",
		"ipv6 mapped":   "::ffff:127.0.0.1",
		"multicast":     "239.1.2.3",
		"documentation": "2001:db8::1",
	} {
		r := resolver.New(resolver.Options{
			Lookup: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(addr)}, nil
			},
			RootCAs:      f.ca.pool,
			PortOverride: f.port(),
			Timeout:      2 * time.Second,
		})
		_, err := r.Resolve(context.Background(), domain, "")
		if err == nil {
			t.Errorf("%s (%s): must be refused", name, addr)
			continue
		}
		if c := mailkey.ClassOf(err); c != mailkey.FailurePolicy {
			t.Errorf("%s (%s): class %q, want %q (%v)", name, addr, c, mailkey.FailurePolicy, err)
		}
	}

	// The policy is enforced per connection, so an authority that answers a
	// public address once and a private one next time is refused the second
	// time — the DNS-rebinding case.
	var calls atomic.Int64
	rebinding := resolver.New(resolver.Options{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			if calls.Add(1) == 1 {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil // cloud metadata
		},
		RootCAs:             f.ca.pool,
		AllowPrivateTargets: true, // even permissive, link-local stays refused
		PortOverride:        f.port(),
		Timeout:             2 * time.Second,
	})
	if _, err := rebinding.Resolve(context.Background(), domain, ""); err != nil {
		t.Fatalf("first resolution should succeed: %v", err)
	}
	_, err := rebinding.Resolve(context.Background(), "other.example", "")
	if err == nil {
		t.Fatal("a rebound link-local address must be refused on the next connection")
	}
	// Refused by OUR policy — not merely unreachable. The distinction matters:
	// a metadata address that happened to time out would pass a weaker test
	// while remaining reachable on a host where it answers.
	if c := mailkey.ClassOf(err); c != mailkey.FailurePolicy {
		t.Fatalf("rebound metadata address: class %q, want %q (%v)", c, mailkey.FailurePolicy, err)
	}
}

// TestPrivateTargetsOptIn: the same loopback authority that the default policy
// refuses is reachable once a deployment opts in. The opt-in is the only switch
// in the package that widens anything, which is why it is tested explicitly.
func TestPrivateTargetsOptIn(t *testing.T) {
	f := newAuthority(t)
	strict := resolver.New(resolver.Options{
		Lookup: f.lookupTo(), RootCAs: f.ca.pool, PortOverride: f.port(), Timeout: 2 * time.Second,
	})
	if _, err := strict.Resolve(context.Background(), domain, ""); err == nil {
		t.Fatal("loopback must be refused by default")
	}
	permissive := newResolver(t, f) // AllowPrivateTargets: true
	if _, err := permissive.Resolve(context.Background(), domain, ""); err != nil {
		t.Fatalf("with the opt-in, loopback must be reachable: %v", err)
	}
}

// TestHTTPRejections: every response shape that is not a manifest, and the class
// each one reports. The classes matter — "absent" is a normal answer, "protocol"
// is an alarm.
func TestHTTPRejections(t *testing.T) {
	type want struct {
		class mailkey.FailureClass
		setup func(*testing.T, *authorityFixture)
	}
	cases := map[string]want{
		"404 is a definitive absence": {mailkey.FailureAbsent, func(_ *testing.T, f *authorityFixture) { f.status = 404 }},
		"410 is a definitive absence": {mailkey.FailureAbsent, func(_ *testing.T, f *authorityFixture) { f.status = 410 }},
		"500 is an http failure":      {mailkey.FailureHTTP, func(_ *testing.T, f *authorityFixture) { f.status = 500 }},
		"401 auth prompt refused":     {mailkey.FailureHTTP, func(_ *testing.T, f *authorityFixture) { f.status = 401 }},
		"204 no content":              {mailkey.FailureHTTP, func(_ *testing.T, f *authorityFixture) { f.status = 204 }},
		"html error page with 200": {mailkey.FailureHTTP, func(_ *testing.T, f *authorityFixture) {
			f.ctype = "text/html; charset=utf-8"
			f.body = []byte("<html>not found</html>")
		}},
		"oversized body": {mailkey.FailureHTTP, func(_ *testing.T, f *authorityFixture) {
			f.body = make([]byte, mailkey.MaxBodyBytes+1)
			f.ctype = mailkey.MediaType
		}},
		"empty body": {mailkey.FailureProtocol, func(_ *testing.T, f *authorityFixture) { f.body = nil }},
		"garbage body": {mailkey.FailureProtocol, func(_ *testing.T, f *authorityFixture) {
			f.body = []byte{0x01, 0x02, 0x03}
		}},
		"manifest for another domain": {mailkey.FailureProtocol, func(t *testing.T, f *authorityFixture) {
			f.body, _ = validManifest(t, "attacker.example", time.Now())
		}},
		"noncanonical trailing byte": {mailkey.FailureProtocol, func(_ *testing.T, f *authorityFixture) {
			f.body = append(append([]byte(nil), f.body...), 0x00)
		}},
	}
	for name, w := range cases {
		f := newAuthority(t)
		w.setup(t, f)
		r := newResolver(t, f)
		_, err := r.Resolve(context.Background(), domain, "")
		if err == nil {
			t.Errorf("%s: must be refused", name)
			continue
		}
		if c := mailkey.ClassOf(err); c != w.class {
			t.Errorf("%s: class %q, want %q (%v)", name, c, w.class, err)
		}
	}
}

// TestExpiredAndOverlongManifest: time policy is enforced on the fetched object,
// not just on the cache.
func TestExpiredAndOverlongManifest(t *testing.T) {
	// Expired: issued and expiring in the past.
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	m, err := manifest.New(domain, past, past.Add(time.Hour), mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	f := newAuthority(t)
	f.body = raw
	r := newResolver(t, f)
	if _, err := r.Resolve(context.Background(), domain, ""); err == nil {
		t.Fatal("an expired manifest must be refused")
	} else if c := mailkey.ClassOf(err); c != mailkey.FailureProtocol {
		t.Fatalf("class %q, want %q", c, mailkey.FailureProtocol)
	}

	// Lifetime beyond the configured ceiling.
	now := time.Now()
	long, err := manifest.New(domain, now, now.Add(365*24*time.Hour), mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	f2 := newAuthority(t)
	f2.body, _ = manifest.Pack(long)
	r2 := newResolver(t, f2)
	if _, err := r2.Resolve(context.Background(), domain, ""); err == nil {
		t.Fatal("a manifest claiming a year of validity must be refused")
	}
}

// TestRedirectsRefused: MKDP1 does not follow redirects, because a redirect
// target is a destination our own derivation never approved.
func TestRedirectsRefused(t *testing.T) {
	f := newAuthority(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://mail.attacker.example/.well-known/mail-key", http.StatusFound)
	}
	r := newResolver(t, f)
	_, err := r.Resolve(context.Background(), domain, "")
	if err == nil {
		t.Fatal("a redirect must be refused")
	}
	if c := mailkey.ClassOf(err); c != mailkey.FailurePolicy {
		t.Fatalf("class %q, want %q (%v)", c, mailkey.FailurePolicy, err)
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("the error should name the refusal: %v", err)
	}
}

// TestSingleFlight: concurrent resolutions of one domain cost one request. This
// is what keeps a header storm from becoming a connection flood.
func TestSingleFlight(t *testing.T) {
	f := newAuthority(t)
	f.delay = 150 * time.Millisecond
	r := newResolver(t, f)

	const callers = 20
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = r.Resolve(context.Background(), domain, "")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if hits := f.hits.Load(); hits != 1 {
		t.Fatalf("%d callers must produce 1 request, got %d", callers, hits)
	}

	// A later resolution is a fresh request — coalescing is per burst, not a
	// cache (caching is the Peer store's job, with the manifest's own expiry).
	if _, err := r.Resolve(context.Background(), domain, ""); err != nil {
		t.Fatal(err)
	}
	if hits := f.hits.Load(); hits != 2 {
		t.Fatalf("a later call must resolve again, got %d hits", hits)
	}
}

// TestTimeout: a slow authority is bounded, and reported as a network failure.
func TestTimeout(t *testing.T) {
	f := newAuthority(t)
	f.delay = 2 * time.Second
	r := newResolver(t, f, func(o *resolver.Options) { o.Timeout = 200 * time.Millisecond })
	start := time.Now()
	_, err := r.Resolve(context.Background(), domain, "")
	if err == nil {
		t.Fatal("a slow authority must time out")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the timeout was not enforced (took %s)", elapsed)
	}
	if c := mailkey.ClassOf(err); c != mailkey.FailureNetwork {
		t.Fatalf("class %q, want %q (%v)", c, mailkey.FailureNetwork, err)
	}
}

// TestUnusableDomains: a domain that cannot be normalized never reaches the
// network at all — the lookup seam is never called.
func TestUnusableDomains(t *testing.T) {
	var looked atomic.Int64
	r := resolver.New(resolver.Options{
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			looked.Add(1)
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Timeout: time.Second,
	})
	for _, bad := range []string{"", "localhost", "127.0.0.1", "example.com:443", "https://example.com", "*.example.com"} {
		_, err := r.Resolve(context.Background(), bad, "")
		if err == nil {
			t.Errorf("%q must be refused", bad)
			continue
		}
		if c := mailkey.ClassOf(err); c != mailkey.FailurePolicy {
			t.Errorf("%q: class %q, want %q", bad, c, mailkey.FailurePolicy)
		}
	}
	if looked.Load() != 0 {
		t.Fatalf("an unusable domain must never be resolved (%d lookups)", looked.Load())
	}
}

// TestCacheLifetime: the cache never outlives the manifest, and a shorter
// max-age from the authority wins.
func TestCacheLifetime(t *testing.T) {
	f := newAuthority(t)
	f.header["Cache-Control"] = "max-age=60, must-revalidate"
	r := newResolver(t, f)
	res, err := r.Resolve(context.Background(), domain, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.ExpiresAt.Before(res.Manifest.ExpiresAt) {
		t.Fatal("a shorter max-age must shorten the cache lifetime")
	}
	if d := res.ExpiresAt.Sub(res.FetchedAt); d > 61*time.Second || d < 59*time.Second {
		t.Fatalf("cache lifetime = %s, want ~60s", d)
	}

	// A longer max-age cannot extend past the manifest's own expiry.
	f2 := newAuthority(t)
	f2.header["Cache-Control"] = "max-age=999999999"
	r2 := newResolver(t, f2)
	res2, err := r2.Resolve(context.Background(), domain, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res2.ExpiresAt.Equal(res2.Manifest.ExpiresAt) {
		t.Fatal("the cache may never outlive the manifest")
	}
}

// TestBodyCapEnforcedBeforeRead: a declared Content-Length over the cap is
// refused without reading a body at all.
func TestBodyCapEnforcedBeforeRead(t *testing.T) {
	f := newAuthority(t)
	f.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mailkey.MediaType)
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(200)
		// Write less than declared; the client must have refused already.
		_, _ = w.Write(make([]byte, 1024))
	}
	r := newResolver(t, f)
	if _, err := r.Resolve(context.Background(), domain, ""); err == nil {
		t.Fatal("an oversized declared length must be refused")
	} else if c := mailkey.ClassOf(err); c != mailkey.FailureHTTP {
		t.Fatalf("class %q, want %q (%v)", c, mailkey.FailureHTTP, err)
	}
}

// delegatedManifest builds a manifest for subject d that CONSENTS to being
// served by the given authority domains (the signed authority sequence).
func delegatedManifest(t *testing.T, d string, authorities []string, now time.Time) []byte {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(d, now.Add(-time.Minute), now.Add(24*time.Hour),
		mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	m.Authority = authorities
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

/*
TestDelegatedResolveAndConsent is the delegation revision's security core.

A domain hosted elsewhere is fetched from its AUTHORITY's host, with the
subject named in ?d= — and what comes back is accepted only because the
manifest ITSELF names that host in its signed authority list. Four cases:

 1. delegated + consenting → accepted, and the request carried ?d=<subject>;
 2. delegated + NOT consenting (the manifest names someone else) → refused:
    this is what makes a hostile a= worthless — it can misroute a request,
    never move a trust decision, and a manifest stolen from one authority
    cannot be re-served from another;
 3. a self-hosted manifest (no authority field) fetched from a delegated
    host → refused, the pre-delegation rule unchanged;
 4. the dual-entry form ([new, old]) is accepted from EITHER host, which is
    what keeps both DNS generations working during a primary switch.
*/
func TestDelegatedResolveAndConsent(t *testing.T) {
	const subject = "customer.example"
	// The fixture's cert is issued for mail.example.com — the AUTHORITY host,
	// not the subject's: exactly the delegated deployment.
	f := newAuthority(t)
	r := newResolver(t, f)
	now := time.Now()

	// 1. Consenting manifest, served by its named authority.
	f.body = delegatedManifest(t, subject, []string{domain}, now)
	var gotQuery string
	f.handler = func(w http.ResponseWriter, req *http.Request) {
		gotQuery = req.URL.Query().Get("d")
		w.Header().Set("Content-Type", mailkey.MediaType)
		_, _ = w.Write(f.body)
	}
	res, err := r.Resolve(context.Background(), subject, domain)
	if err != nil {
		t.Fatalf("delegated resolve: %v", err)
	}
	if res.Manifest.Domain != subject {
		t.Fatalf("subject = %q", res.Manifest.Domain)
	}
	if gotQuery != subject {
		t.Fatalf("the authority must be told the subject via ?d=, got %q", gotQuery)
	}

	// 2. The same host serving a manifest that consents to somebody ELSE.
	f.body = delegatedManifest(t, subject, []string{"other-provider.example"}, now)
	if _, err := r.Resolve(context.Background(), subject, domain); err == nil {
		t.Fatal("a manifest whose signed authority does not name the serving host must be refused")
	} else if !strings.Contains(err.Error(), "authority") {
		t.Fatalf("refusal must name the consent failure: %v", err)
	}

	// 3. A self-hosted manifest cannot be served from a delegated host.
	f.body = delegatedManifest(t, subject, nil, now)
	if _, err := r.Resolve(context.Background(), subject, domain); err == nil {
		t.Fatal("a manifest with no authority consents only to its own host")
	}

	// 4. Mid-switch: consent to BOTH generations is accepted from either.
	f.body = delegatedManifest(t, subject, []string{"new-primary.example", domain}, now)
	if _, err := r.Resolve(context.Background(), subject, domain); err != nil {
		t.Fatalf("a dual-authority manifest must be accepted from the old host too: %v", err)
	}
}
