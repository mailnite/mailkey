/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package discovery parses MKDP1 observations and derives the protocol's fixed
names from a domain.

Two rules run through everything here:

 1. An observation carries NO key material. A DNS record and a Mail-Key header
    can say "this domain speaks MKDP1, and the manifest I saw had this id" —
    nothing more. Parsing them can therefore never install anything.

 2. Names are DERIVED, never accepted. There is no field in any MKDP1
    observation that can specify a host, a port, a path or a URL. Given the
    normalized domain d, the TXT owner name is always _mailkey.<d> and the
    authority URL is always https://mail.<d>/.well-known/mail-key. This is what
    keeps a hostile header from turning the resolver into an open request
    proxy: the only thing an attacker influences is d, and Normalize bounds
    that to a public DNS domain.
*/
package discovery

import (
	"net"
	"net/url"
	"strings"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"golang.org/x/xerrors"
)

// maxTXTLen bounds one TXT string before parsing.
const maxTXTLen = 512

// MaxHeaderLen bounds a Mail-Key header value before parsing. The MKDP1 header
// is tiny (roughly 70 bytes); anything far larger is not a header we wrote.
const MaxHeaderLen = 512

/*
Normalize converts an email domain to its protocol form: a lowercase ASCII
IDNA A-label with no trailing dot, scheme, port, user info, wildcard or IP
literal.

The implementation lives in the ROOT package (mailkey.NormalizeDomain) because
the canonical form is protocol-wide: manifest packing must reject a domain the
resolver would normalize differently, and manifest cannot import discovery (the
dependency runs the other way). One rule, one implementation, reachable from
both sides — this name stays as the discovery-side spelling every caller and
the published vectors already use.
*/
func Normalize(domain string) (string, error) { return mailkey.NormalizeDomain(domain) }

// DNSName is the TXT owner name that advertises MKDP1 for a domain.
func DNSName(domain string) (string, error) {
	d, err := Normalize(domain)
	if err != nil {
		return "", err
	}
	return mailkey.DNSPrefix + "." + d, nil
}

// AuthorityHost is the only host MKDP1 will talk to for a domain: the mail
// host of the domain's AUTHORITY. authority is the a= observation ("" =
// self-hosted, the authority is the domain itself). Both inputs pass the same
// Normalize bounds, so the reachable set stays "mail.<some public domain>" —
// scheme, port and path are fixed elsewhere, and no observation can widen
// this into a URL.
func AuthorityHost(domain, authority string) (string, error) {
	d, err := Normalize(domain)
	if err != nil {
		return "", err
	}
	if authority != "" {
		a, aerr := Normalize(authority)
		if aerr != nil {
			return "", xerrors.Errorf("authority: %w", aerr)
		}
		d = a
	}
	return mailkey.HostPrefix + "." + d, nil
}

/*
DomainCandidatesOf is the server side of discovery: which domain's manifest a
request addressed to this host is asking for. It is the inverse of AuthorityHost,
and it exists in the library because getting it wrong is a host-header bug — an
implementation that trims the "mail." prefix by string surgery skips
normalization and can be fed a port, an uppercase label, a trailing dot, or an
IP literal.

It returns candidates in order of authority, most specific first, because one
host can legitimately mean two domains:

	mail.example.com  →  example.com        (the authority for example.com)
	                  →  mail.example.com   (a domain literally named that)

MKDP1 defines the first reading, so it is tried first; the second exists because
a domain named "mail.example.com" is a real thing an operator may host, and
because a server whose webmail and authority share one address also sees requests
whose Host is the bare domain. The caller decides between candidates by asking
which one it actually hosts — never by trusting the host header — so the order
matters only when a server hosts BOTH readings, and then the protocol's own
meaning wins.

A host that cannot be a domain at all (an IP, a port that is not 443, an empty
label) yields no candidates, so the caller has nothing to answer for.
*/
func DomainCandidatesOf(host string) []string {
	h := strings.TrimSpace(host)
	if h == "" {
		return nil
	}
	// A Host header may carry a port. Only the default port is acceptable: a
	// request that arrived on some other port did not reach the authority MKDP1
	// describes, and answering it would paper over the misconfiguration.
	if hostOnly, port, err := net.SplitHostPort(h); err == nil {
		if port != "443" {
			return nil
		}
		h = hostOnly
	}
	// Normalize rejects IPs, wildcards, single labels and ports, and pins the
	// result to its own stable normal form.
	full, err := Normalize(h)
	if err != nil {
		return nil
	}
	var out []string
	if rest, ok := cutPrefixLabel(full, mailkey.HostPrefix); ok {
		if d, err := Normalize(rest); err == nil {
			out = append(out, d)
		}
	}
	return append(out, full)
}

// cutPrefixLabel removes a leading DNS label, and only a whole label:
// "mail.example.com" gives "example.com", while "mailx.example.com" gives
// nothing.
func cutPrefixLabel(host, label string) (string, bool) {
	p := label + "."
	if !strings.HasPrefix(host, p) || len(host) == len(p) {
		return "", false
	}
	return host[len(p):], true
}

// DiscoveryURL derives the complete authority URL for a subject domain and
// its (possibly empty) delegated authority. It accepts two Normalize-bounded
// DOMAINS and nothing else: there is no code path in MKDP1 that accepts a
// caller-supplied URL, host or port. The subject always rides as ?d= — one
// uniform request shape whether self-hosted or delegated — which is what
// lets one host serve many domains' manifests.
func DiscoveryURL(domain, authority string) (*url.URL, error) {
	host, err := AuthorityHost(domain, authority)
	if err != nil {
		return nil, err
	}
	d, err := Normalize(domain)
	if err != nil {
		return nil, err
	}
	q := url.Values{mailkey.SubjectQueryParam: []string{d}}
	return &url.URL{Scheme: "https", Host: host, Path: mailkey.WellKnownPath, RawQuery: q.Encode()}, nil
}

// ParseDNS reads the TXT strings at _mailkey.<domain> into advertisements.
// Malformed records are skipped (with the reason returned for diagnostics)
// rather than failing the set: one broken record must not hide a good one.
//
// Several DIFFERENT valid ids or identity fingerprints mean the DNS view is
// inconsistent — the caller records that and resolves over HTTPS. It does not
// pick a winner; there is no rule by which one unauthenticated record beats
// another.
func ParseDNS(domain string, txt []string) (ads []mailkey.Advertisement, skipped []error, err error) {
	d, err := Normalize(domain)
	if err != nil {
		return nil, nil, err
	}
	for _, rec := range txt {
		if len(rec) > maxTXTLen {
			skipped = append(skipped, xerrors.Errorf("txt record longer than %d bytes", maxTXTLen))
			continue
		}
		ad, perr := parseParams(rec, d, false)
		if perr != nil {
			skipped = append(skipped, perr)
			continue
		}
		ads = append(ads, ad)
	}
	return ads, skipped, nil
}

// ParseHeader reads a Mail-Key header value. The header names its own subject
// domain (d=); d= and the optional delegated authority domain a= are normalized
// here. The parser never accepts an arbitrary host or URL, and the caller must
// not use a= to route first contact without separate authentication.
func ParseHeader(headerValue string) (mailkey.Advertisement, error) {
	if len(headerValue) > MaxHeaderLen {
		return mailkey.Advertisement{}, xerrors.Errorf("header: longer than %d bytes", MaxHeaderLen)
	}
	return parseParams(headerValue, "", true)
}

// FormatHeader renders the header a server stamps on its own outbound mail.
// authority is the delegated authority domain ("" = self-hosted). The header
// carries it for diagnostics and post-pin refreshes; because a header is
// attacker-controlled at first contact, it cannot authorize its own route.
func FormatHeader(domain string, id mailkey.ManifestID, authority string) (string, error) {
	d, err := Normalize(domain)
	if err != nil {
		return "", err
	}
	out := "v=" + mailkey.Version + "; d=" + d + "; id=" + encodeID(id)
	if authority != "" {
		a, aerr := Normalize(authority)
		if aerr != nil {
			return "", xerrors.Errorf("authority: %w", aerr)
		}
		if a != d {
			out += "; a=" + a
		}
	}
	return out + "; mode=" + mailkey.Mode, nil
}

/*
FormatDNS renders the TXT value a server publishes for its own domain.

It advertises the identity FINGERPRINT, not the manifest id. The id changes on
every manifest re-issue, so a published record goes stale within days of being
written — which defeats its purpose and, for any implementation that refreshes on
disagreement, produces one authority fetch per message. The fingerprint changes
only on identity rollover: never on an ordinary X25519 rotation, never on manifest
renewal. A record should carry only values whose change is rare and meaningful,
because an alert that fires routinely is an alert that gets ignored.

A domain with no identity key yet falls back to the deprecated id= form, so it
still publishes something a resolver can act on.
*/
// authority is the delegated authority domain ("" = self-hosted); a caller
// passing a non-normalized value gets it normalized here — the record is what
// operators paste into zones, so it must come out in A-label form.
func FormatDNS(fp mailkey.Fingerprint, hasFP bool, id mailkey.ManifestID, authority string) string {
	out := "v=" + mailkey.Version
	if hasFP {
		out += "; fp=" + manifest.EncodeID(fp)
	} else {
		out += "; id=" + encodeID(id)
	}
	if a, err := Normalize(authority); authority != "" && err == nil {
		out += "; a=" + a
	}
	return out + "; mode=" + mailkey.Mode
}

/*
parseParams parses the shared "k=v; k=v" grammar. requireDomain marks the header
form, where d= is mandatory; the DNS form takes its domain from the owner name
that was queried.

v, id and mode are all REQUIRED (02-MKDP1-PROTOCOL.md §2 and §3). They used to
be accepted as optional, which was wrong in two different ways. An unknown or
absent MODE is the protocol asking to be interpreted some way we do not know;
guessing "https" is exactly the guess a future mode would punish, and a client
that cannot name the semantics of an object must not act on it. And an
advertisement with no ID cannot do the only job an advertisement has — say which
manifest to expect — so accepting one produced peer records with nothing to
check, from input anybody can send.

Refusing is cheap here: both forms treat a parse failure as "not an
advertisement", which the spec requires anyway (a malformed record MUST be
ignored and recorded diagnostically).
*/
func parseParams(s, domain string, requireDomain bool) (mailkey.Advertisement, error) {
	var zero mailkey.Advertisement
	fields := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return zero, xerrors.Errorf("advertisement: %q is not k=v", part)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if _, dup := fields[k]; dup {
			return zero, xerrors.Errorf("advertisement: duplicate field %q", k)
		}
		fields[k] = v
	}
	if fields["v"] != mailkey.Version {
		return zero, xerrors.Errorf("advertisement: unsupported version %q", fields["v"])
	}
	switch m, ok := fields["mode"]; {
	case !ok:
		return zero, xerrors.New("advertisement: missing mode=")
	case m != mailkey.Mode:
		return zero, xerrors.Errorf("advertisement: unsupported mode %q", m)
	}
	ad := mailkey.Advertisement{Version: mailkey.Version, Mode: mailkey.Mode, Domain: domain}
	if dv, ok := fields["d"]; ok {
		nd, err := Normalize(dv)
		if err != nil {
			return zero, xerrors.Errorf("advertisement: %w", err)
		}
		// In the DNS form the owner name already fixed the domain; a d= field
		// that disagrees is a malformed record, not an override.
		if domain != "" && nd != domain {
			return zero, xerrors.Errorf("advertisement: d=%q does not match %q", nd, domain)
		}
		ad.Domain = nd
	} else if requireDomain {
		return zero, xerrors.New("advertisement: missing d=")
	}
	// a= names the AUTHORITY DOMAIN whose mail host serves this domain's
	// manifests (delegated authority). It is a DOMAIN under the same Normalize
	// bounds as d — the one bounded degree of freedom the delegation revision
	// adds — never a host, port, path or URL. A self-pointing a= collapses to
	// the self-hosted form so Authority != "" always MEANS delegated.
	if av, present := fields["a"]; present {
		na, aerr := Normalize(av)
		if aerr != nil {
			return zero, xerrors.Errorf("advertisement: a=: %w", aerr)
		}
		if na != ad.Domain {
			ad.Authority = na
		}
	}
	// Reject any field that could name a target: MKDP1 derives the host.
	for _, forbidden := range []string{"url", "host", "port", "path", "endpoint", "pk", "key", "seq"} {
		if _, present := fields[forbidden]; present {
			return zero, xerrors.Errorf("advertisement: field %q is not part of MKDP1", forbidden)
		}
	}
	// fp names the domain's signing IDENTITY; id names one fetch. Both are
	// observations and neither installs anything, but their lifetimes differ by
	// orders of magnitude, which is why fp replaced id as the thing worth
	// publishing: id changes on every manifest re-issue (issued_at is inside the
	// hashed bytes), so a record written today is stale within days, and an
	// implementation that refreshes on disagreement ends up fetching the
	// authority once per message. fp changes only on identity rollover.
	//
	// A malformed fp makes the RECORD malformed. It must never degrade to "no
	// fingerprint": that would let an attacker who can corrupt one character
	// turn corroboration off silently, which is the whole value DNS adds.
	if fpv, present := fields["fp"]; present {
		fp, ferr := decodeID(fpv)
		if ferr != nil {
			return zero, xerrors.Errorf("advertisement: fp: %w", ferr)
		}
		ad.Fingerprint, ad.HasFP = mailkey.Fingerprint(fp), true
	}
	if idv, present := fields["id"]; present {
		id, ierr := decodeID(idv)
		if ierr != nil {
			return zero, xerrors.Errorf("advertisement: id: %w", ierr)
		}
		ad.ManifestID, ad.HasID = id, true
	}
	// One or the other must be there. A record naming neither cannot do the only
	// job an advertisement has — say which object the authority should be holding
	// — and acting on it would mean fetching on the strength of "something
	// exists", which any observer could assert.
	if !ad.HasID && !ad.HasFP {
		return zero, xerrors.New("advertisement: needs fp= (or the deprecated id=)")
	}
	return ad, nil
}
