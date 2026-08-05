/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package resolver is the MKDP1 authority client: the ONLY code that can install
a key, and the only code a remote party can cause to run.

That second property is what shapes this package. A stranger's email carrying a
Mail-Key header makes this server issue an HTTPS request to a domain the
stranger chose, so the request is treated as hostile from both ends: the target
must be provably the domain's own authority, and the response must be provably
a canonical MKDP1 manifest before any of it is believed.

Every safeguard is on by default and none of them is a caller's option:

	target      derived from the normalized domain — no host, port, path or URL
	            from any observation ever reaches the network layer
	transport   HTTPS only, port 443 only, GET only, redirects refused
	addresses   every resolved address checked against AddressPolicy on every
	            connection (the DNS-rebinding defense), private ranges opt-in
	TLS         WebPKI chain and hostname validation for mail.<domain>, TLS 1.2+
	transfer    whole-request deadline, 16 KiB body cap enforced before reading
	response    status 200 required, media type checked, canonical parse,
	            requested domain pinned, kid recomputed, validity enforced
	load        per-domain single flight, global concurrency cap

The single injection seam is name resolution (LookupFunc). It cannot weaken
anything: the address policy runs on whatever it returns, and TLS validates
against the derived hostname regardless of where the connection went.
*/
package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/manifest"
	"golang.org/x/xerrors"
)

// authorityPort is the only port MKDP1 speaks to.
const authorityPort = "443"

// Defaults for the transfer budget. They are deliberately tight: the endpoint
// serves a few hundred prebuilt bytes, so a slow authority is a broken one, and
// waiting on it costs the outbound path.
const (
	DefaultTimeout     = 8 * time.Second
	DefaultDialTimeout = 4 * time.Second
	DefaultConcurrency = 8
)

// Options configures a Resolver. The zero value is usable: every field falls
// back to a safe default, and no field can turn a safeguard off except
// AllowPrivateTargets, which exists for split-DNS deployments and is off here.
type Options struct {
	// Timeout bounds one whole resolution: connect, TLS, request, body.
	Timeout time.Duration
	// DialTimeout bounds one connection attempt.
	DialTimeout time.Duration
	// MaxBodyBytes caps the response body. Defaults to mailkey.MaxBodyBytes
	// (16 KiB) and is clamped to it — a caller may tighten, never loosen.
	MaxBodyBytes int64
	// Limits are the manifest validity bounds.
	Limits manifest.Limits
	// AllowPrivateTargets permits loopback/private/link-local authorities.
	// Off by default; see AddressPolicy.
	AllowPrivateTargets bool
	// PortOverride replaces the fixed authority port. It exists for tests and
	// for split-DNS deployments that publish the endpoint elsewhere, and it is
	// honoured ONLY together with AllowPrivateTargets — so a default
	// configuration can never be pointed at a port other than 443, whatever
	// else it sets.
	PortOverride string
	// MaxConcurrent caps resolutions in flight across all domains, so a header
	// storm cannot turn into an outbound connection flood.
	MaxConcurrent int
	// Lookup replaces name resolution (tests, a custom resolver). nil = system.
	Lookup LookupFunc
	// RootCAs replaces the WebPKI trust store. nil = system pool. Supplying a
	// pool NARROWS trust to it; it never disables verification.
	RootCAs *x509.CertPool
	// UserAgent identifies this client to the authority.
	UserAgent string
	// Now is the clock, for tests.
	Now func() time.Time
}

// Resolver fetches and validates manifests from MKDP1 authorities.
type Resolver struct {
	opts   Options
	policy AddressPolicy
	// port is the authority port actually dialed: 443, unless a deployment
	// deliberately opted into both private targets and an override.
	port string

	// inflight coalesces concurrent resolutions of the same domain into one
	// request: DNS and header observations arrive in bursts, and a burst must
	// cost one fetch, not one per observation.
	mu       sync.Mutex
	inflight map[string]*call

	// sem is the global concurrency cap.
	sem chan struct{}
}

// call is one in-flight resolution other callers may join.
type call struct {
	done chan struct{}
	res  mailkey.Result
	err  error
}

var _ mailkey.Resolver = (*Resolver)(nil)

// New builds a Resolver. It never returns an unsafe configuration: out-of-range
// values are replaced with defaults rather than honoured.
func New(opts Options) *Resolver {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.DialTimeout <= 0 || opts.DialTimeout > opts.Timeout {
		opts.DialTimeout = min(DefaultDialTimeout, opts.Timeout)
	}
	if opts.MaxBodyBytes <= 0 || opts.MaxBodyBytes > mailkey.MaxBodyBytes {
		opts.MaxBodyBytes = mailkey.MaxBodyBytes
	}
	if opts.Limits.MaxLifetime <= 0 || opts.Limits.MaxClockSkew <= 0 {
		d := manifest.DefaultLimits()
		if opts.Limits.MaxLifetime <= 0 {
			opts.Limits.MaxLifetime = d.MaxLifetime
		}
		if opts.Limits.MaxClockSkew <= 0 {
			opts.Limits.MaxClockSkew = d.MaxClockSkew
		}
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = DefaultConcurrency
	}
	if opts.Lookup == nil {
		opts.Lookup = systemLookup
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "mailkey/1 (MKDP1)"
	}
	port := authorityPort
	if opts.AllowPrivateTargets && opts.PortOverride != "" {
		port = opts.PortOverride
	}
	return &Resolver{
		opts:     opts,
		policy:   AddressPolicy{AllowPrivate: opts.AllowPrivateTargets},
		port:     port,
		inflight: map[string]*call{},
		sem:      make(chan struct{}, opts.MaxConcurrent),
	}
}

// Resolve fetches, validates and returns the domain's effective manifest.
//
// Concurrent calls for the same domain share one request: the first caller
// performs it and the rest wait for its outcome. That keeps an observation
// burst — a mail flood, a DNS record change seen by many workers — down to a
// single connection to the authority.
// authority is the DELEGATED authority domain from the caller's freshest
// advertisement ("" = self-hosted). It is a routing observation: it decides
// which mail host is dialed and nothing else — the manifest must still bind
// the SUBJECT domain, and (once the signed authority lands) the serving host
// must appear in the manifest's own authority list.
func (r *Resolver) Resolve(ctx context.Context, domain, authority string) (mailkey.Result, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailurePolicy, domain, err)
	}
	a := ""
	if authority != "" {
		if a, err = discovery.Normalize(authority); err != nil {
			return mailkey.Result{}, mailkey.Fail(mailkey.FailurePolicy, domain, xerrors.Errorf("authority: %w", err))
		}
		if a == d {
			a = "" // self-pointing hint collapses to self-hosted
		}
	}
	// The in-flight key carries the authority too: two callers resolving the
	// same domain through DIFFERENT authority hints must not share an outcome
	// (one of them may be following a stale record mid-transition).
	key := d
	if a != "" {
		key = d + "@" + a
	}

	r.mu.Lock()
	if c, ok := r.inflight[key]; ok {
		r.mu.Unlock()
		select {
		case <-c.done:
			return c.res, c.err
		case <-ctx.Done():
			return mailkey.Result{}, mailkey.Fail(mailkey.FailureNetwork, d, ctx.Err())
		}
	}
	c := &call{done: make(chan struct{})}
	r.inflight[key] = c
	r.mu.Unlock()

	c.res, c.err = r.fetch(ctx, d, a)

	r.mu.Lock()
	delete(r.inflight, key)
	r.mu.Unlock()
	close(c.done)
	return c.res, c.err
}

// fetch performs one resolution: acquire a slot, build the request from the
// domain alone, validate everything.
func (r *Resolver) fetch(ctx context.Context, d, authority string) (mailkey.Result, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return mailkey.Result{}, mailkey.Fail(mailkey.FailureNetwork, d, ctx.Err())
	}

	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	u, err := discovery.DiscoveryURL(d, authority)
	if err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailurePolicy, d, err)
	}
	host, err := discovery.AuthorityHost(d, authority)
	if err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailurePolicy, d, err)
	}
	// With an override in force the URL carries the port; the TLS ServerName
	// stays the derived hostname either way, so certificate validation is
	// unaffected by where the connection went.
	if r.port != authorityPort {
		u.Host = net.JoinHostPort(host, r.port)
	}

	client := r.clientFor(d, host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailurePolicy, d, err)
	}
	req.Header.Set("Accept", mailkey.MediaType)
	req.Header.Set("User-Agent", r.opts.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return mailkey.Result{}, classifyTransportError(d, err)
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close.
		_, _ = io.CopyN(io.Discard, resp.Body, 1<<10)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		// A definitive "no MKDP1 here" — not a failure to retry hard.
		return mailkey.Result{}, mailkey.Failf(mailkey.FailureAbsent, d,
			"the authority answered %d: this domain does not publish an MKDP1 manifest", resp.StatusCode)
	case http.StatusUnauthorized, http.StatusProxyAuthRequired:
		// The endpoint is public by definition; an auth prompt means we are
		// talking to something that is not the MKDP1 authority.
		return mailkey.Result{}, mailkey.Failf(mailkey.FailureHTTP, d,
			"the authority requested authentication (%d); the MKDP1 endpoint is public", resp.StatusCode)
	default:
		return mailkey.Result{}, mailkey.Failf(mailkey.FailureHTTP, d, "the authority answered %d", resp.StatusCode)
	}

	// Content-Length, when present, is checked before a single byte is read.
	if resp.ContentLength > r.opts.MaxBodyBytes {
		return mailkey.Result{}, mailkey.Failf(mailkey.FailureHTTP, d,
			"the response declares %d bytes, over the %d byte limit", resp.ContentLength, r.opts.MaxBodyBytes)
	}
	if err := checkMediaType(resp.Header.Get("Content-Type")); err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailureHTTP, d, err)
	}

	// Read one byte past the cap: if it arrives, the body is oversized.
	body, err := io.ReadAll(io.LimitReader(resp.Body, r.opts.MaxBodyBytes+1))
	if err != nil {
		return mailkey.Result{}, classifyTransportError(d, err)
	}
	if int64(len(body)) > r.opts.MaxBodyBytes {
		return mailkey.Result{}, mailkey.Failf(mailkey.FailureHTTP, d,
			"the response body exceeds the %d byte limit", r.opts.MaxBodyBytes)
	}

	// From here on the bytes are the object: parse canonically, pin the
	// requested domain, recompute kid, enforce validity.
	m, err := manifest.ParseCanonical(body, d)
	if err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailureProtocol, d, err)
	}
	now := r.opts.Now()
	if err := manifest.Validate(m, now, r.opts.Limits); err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailureProtocol, d, err)
	}
	/*
		The consent check: the host we ACTUALLY fetched from must be one the
		domain itself named in its signed manifest.

		This is what makes delegated authority safe. The a= observation that
		sent us here is unauthenticated — anyone can publish a record pointing
		at anyone. Without this check a hostile record would make every
		resolver on the internet fetch from a victim host and, worse, could
		let a manifest stolen from one authority be re-served from another.
		With it, the domain's own signature decides where its manifests may
		live: a misdirected request gets a 404 or a manifest whose consent
		does not name the host we reached, and dies here.

		Self-hosted manifests (no authority field) consent to exactly one
		host — their own — which is the pre-delegation rule, unchanged.
	*/
	if err := checkAuthorityConsent(m, host); err != nil {
		return mailkey.Result{}, mailkey.Fail(mailkey.FailureProtocol, d, err)
	}

	out := mailkey.Result{
		Manifest:   m,
		ManifestID: manifest.ManifestIDOf(body),
		Raw:        body,
		FetchedAt:  now,
		// The cache may never outlive the manifest, and an authority that asks
		// for a shorter life gets it.
		ExpiresAt: cacheUntil(m.ExpiresAt, now, resp.Header.Get("Cache-Control")),
		TLSHost:   host,
	}
	/*
		The detached identity proof, read from the SAME response as the body.

		A malformed proof does not fail the resolution, and that is deliberate:
		the manifest is WebPKI-authenticated and independently valid, so refusing
		it here would take a domain's encryption offline on the strength of a
		header — the failure an attacker who can only corrupt headers would
		choose. What the trust layer needs is the DISTINCTION, so it is recorded:
		Proof set means "this domain signs and the signature checks out against
		the key it presented", ProofError set means "a proof was present and
		wrong", and both empty means "this domain does not sign".

		Only the peer's pin can turn any of those into a decision. Verifying here
		and treating success as authentication would be the mistake the whole
		extension exists to avoid — an attacker's own proof verifies perfectly.
	*/
	if proof, found, perr := identity.ReadProof(resp.Header); perr != nil {
		out.ProofError = perr.Error()
	} else if found {
		if cerr := identity.Check(proof, d, body); cerr != nil {
			out.ProofError = cerr.Error()
		} else {
			out.Proof = proof
		}
	}
	return out, nil
}

// clientFor builds a single-use client pinned to this domain's authority. A
// fresh transport per resolution costs one handshake and buys certainty: no
// connection, DNS answer or TLS session is reused across domains, and the
// dialer carries this domain's identity for error attribution.
// checkAuthorityConsent enforces that fetchedHost is the mail host of some
// authority the manifest itself names (or of the domain, when it names none).
func checkAuthorityConsent(m mailkey.Manifest, fetchedHost string) error {
	allowed := m.Authority
	if len(allowed) == 0 {
		allowed = []string{m.Domain}
	}
	for _, a := range allowed {
		host, err := discovery.AuthorityHost(a, "")
		if err != nil {
			continue // a manifest entry that is not a domain consents to nothing
		}
		if strings.EqualFold(host, fetchedHost) {
			return nil
		}
	}
	return xerrors.Errorf("manifest served by %q, which its signed authority does not name (%v)", fetchedHost, allowed)
}

func (r *Resolver) clientFor(domain, host string) *http.Client {
	d := &dialer{
		policy:  r.policy,
		lookup:  r.opts.Lookup,
		port:    r.port,
		timeout: r.opts.DialTimeout,
		domain:  domain,
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:            d.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: r.opts.RootCAs},
			TLSHandshakeTimeout:    r.opts.DialTimeout,
			ResponseHeaderTimeout:  r.opts.Timeout,
			DisableKeepAlives:      true,
			DisableCompression:     true,
			ForceAttemptHTTP2:      true,
			MaxResponseHeaderBytes: 8 << 10,
			// No proxy: the authority is reached directly or not at all. A
			// proxy would break the address policy's guarantee, since the
			// policy could then only see the proxy's address.
			Proxy: nil,
		},
		// Redirects are refused outright (spec §4). Following one would let an
		// authority hand us off to a target our own derivation never approved.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return mailkey.Failf(mailkey.FailurePolicy, domain,
				"MKDP1 does not follow redirects (the authority pointed at %s)", req.URL.Redacted())
		},
		Timeout: r.opts.Timeout,
	}
}

// checkMediaType refuses a response whose declared type cannot be an MKDP1
// manifest. A blank or octet-stream type is tolerated (the media type is a
// SHOULD in the spec); an HTML error page served with status 200 is not.
//
// The list is deliberately permissive about which MessagePack spelling an
// authority chose — including the vendor type MKDP1 used before settling on the
// generic one — because the media type is a hint. What actually decides whether
// a response is a manifest is the canonical parse that follows, and no content
// type can talk its way past that.
func checkMediaType(ct string) error {
	if ct == "" {
		return nil
	}
	base, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return xerrors.Errorf("unparsable content type %q", ct)
	}
	switch base {
	case mailkey.MediaType, "application/octet-stream", "application/x-msgpack",
		"application/vnd.mailnite.mail-key+msgpack":
		return nil
	default:
		return xerrors.Errorf("content type %q is not an MKDP1 manifest", base)
	}
}

// cacheUntil bounds the cache lifetime by the manifest's own expiry, shortened
// by a max-age the authority asked for.
func cacheUntil(expiresAt, now time.Time, cacheControl string) time.Time {
	if cacheControl == "" {
		return expiresAt
	}
	for _, part := range strings.Split(cacheControl, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(k) != "max-age" {
			continue
		}
		v = strings.TrimSpace(v)
		secs, err := strconv.Atoi(v)
		if err != nil || secs < 0 {
			continue
		}
		if until := now.Add(time.Duration(secs) * time.Second); until.Before(expiresAt) {
			return until
		}
	}
	return expiresAt
}

// classifyTransportError sorts a client error into a class a caller can act on:
// a TLS failure on a domain that used to validate deserves attention, a refused
// connection does not.
func classifyTransportError(domain string, err error) error {
	// A policy or network class assigned by our own dialer wins — it is more
	// specific than anything inferable from the wrapped transport error.
	if c := mailkey.ClassOf(err); c != "" {
		return err
	}
	var certErr *tls.CertificateVerificationError
	if xerrors.As(err, &certErr) {
		return mailkey.Fail(mailkey.FailureTLS, domain, err)
	}
	var hostErr x509.HostnameError
	if xerrors.As(err, &hostErr) {
		return mailkey.Fail(mailkey.FailureTLS, domain, err)
	}
	var unknownAuthority x509.UnknownAuthorityError
	if xerrors.As(err, &unknownAuthority) {
		return mailkey.Fail(mailkey.FailureTLS, domain, err)
	}
	var invalidCert x509.CertificateInvalidError
	if xerrors.As(err, &invalidCert) {
		return mailkey.Fail(mailkey.FailureTLS, domain, err)
	}
	return mailkey.Fail(mailkey.FailureNetwork, domain, err)
}

/*
ResolveIdentityChain implements mailkey.IdentityChainResolver: the hardened
fetch of https://mail.<d>/.well-known/mail-key-identity.

Every protection the manifest fetch has applies unchanged — the derived
authority host, WebPKI validation with the pinned ServerName, the concurrency
semaphore, the declared-length check before a byte is read — because this
resource moves TRUST ANCHORS, and a fetch of it deserves nothing less than the
fetch it exists to explain. The one difference is the size bound: a chain is
bigger than a manifest, so the cap is the §5.2 chain bound rather than the
manifest's.

The body is returned raw. The caller walks it from its own pin; nothing here
vouches for anything.
*/
// authority mirrors Resolve's: the delegated authority hint ("" = self).
func (r *Resolver) ResolveIdentityChain(ctx context.Context, domain, authority string) ([]byte, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return nil, mailkey.Fail(mailkey.FailurePolicy, domain, err)
	}
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, mailkey.Fail(mailkey.FailureNetwork, d, ctx.Err())
	}
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	host, err := discovery.AuthorityHost(d, authority)
	if err != nil {
		return nil, mailkey.Fail(mailkey.FailurePolicy, d, err)
	}
	q := url.Values{mailkey.SubjectQueryParam: []string{d}}
	u := &url.URL{Scheme: "https", Host: host, Path: identity.ResourcePath, RawQuery: q.Encode()}
	if r.port != authorityPort {
		u.Host = net.JoinHostPort(host, r.port)
	}
	client := r.clientFor(d, host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, mailkey.Fail(mailkey.FailurePolicy, d, err)
	}
	req.Header.Set("Accept", mailkey.MediaType)
	req.Header.Set("User-Agent", r.opts.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, classifyTransportError(d, err)
	}
	defer func() {
		_, _ = io.CopyN(io.Discard, resp.Body, 1<<10)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		// 404 is the ordinary answer of a domain that signs but has never
		// rotated an identity resource into existence, and of software that
		// predates the resource. Not an alarm — the caller's refusal stands.
		return nil, mailkey.Failf(mailkey.FailureAbsent, d, "no identity resource: %d", resp.StatusCode)
	}
	if resp.ContentLength > int64(identity.MaxChainBytes) {
		return nil, mailkey.Failf(mailkey.FailureHTTP, d,
			"the identity resource declares %d bytes, over the %d byte limit", resp.ContentLength, identity.MaxChainBytes)
	}
	if err := checkMediaType(resp.Header.Get("Content-Type")); err != nil {
		return nil, mailkey.Fail(mailkey.FailureHTTP, d, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(identity.MaxChainBytes)+1))
	if err != nil {
		return nil, classifyTransportError(d, err)
	}
	if len(body) > identity.MaxChainBytes {
		return nil, mailkey.Failf(mailkey.FailureHTTP, d,
			"the identity resource exceeds the %d byte limit", identity.MaxChainBytes)
	}
	return body, nil
}
