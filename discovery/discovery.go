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
	"golang.org/x/net/idna"
	"golang.org/x/xerrors"
)

// maxDomainLen is the DNS limit on a presentation-format name.
const maxDomainLen = 253

// maxTXTLen bounds one TXT string before parsing.
const maxTXTLen = 512

// MaxHeaderLen bounds a Mail-Key header value before parsing. The MKDP1 header
// is tiny (roughly 70 bytes); anything far larger is not a header we wrote.
const MaxHeaderLen = 512

// idnaProfile is deliberately strict: it maps to an ASCII A-label, validates
// the label structure, and refuses anything it cannot represent. A domain that
// does not survive this never reaches the network.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
	idna.BidiRule(),
)

// Normalize converts an email domain to its protocol form: a lowercase ASCII
// IDNA A-label with no trailing dot, no scheme, port, path, user info,
// wildcard or IP literal.
//
// This is the security boundary for every name that comes off the wire. It is
// intentionally restrictive — an IP literal, a name with a port, or anything
// resembling a URL is rejected outright rather than coerced into something
// dialable.
func Normalize(domain string) (string, error) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return "", xerrors.New("domain: empty")
	}
	if len(d) > maxDomainLen+1 { // +1 tolerates a trailing dot before trimming
		return "", xerrors.Errorf("domain: longer than %d characters", maxDomainLen)
	}
	// Reject URL-ish and address-ish shapes before IDNA sees them: these are
	// the shapes that would otherwise smuggle a target past the derivation.
	if strings.ContainsAny(d, "/\\?#@ \t\r\n%") {
		return "", xerrors.Errorf("domain: %q must be a bare domain name", domain)
	}
	if strings.Contains(d, "://") {
		return "", xerrors.Errorf("domain: %q must not contain a scheme", domain)
	}
	if strings.Contains(d, ":") {
		return "", xerrors.Errorf("domain: %q must not contain a port", domain)
	}
	if strings.HasPrefix(d, "*") || strings.Contains(d, "*") {
		return "", xerrors.Errorf("domain: %q must not be a wildcard", domain)
	}
	if strings.HasPrefix(d, "[") {
		return "", xerrors.Errorf("domain: %q must not be an IP literal", domain)
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", xerrors.New("domain: empty")
	}
	if net.ParseIP(d) != nil {
		return "", xerrors.Errorf("domain: %q is an IP address, not a domain", domain)
	}
	ascii, err := idnaProfile.ToASCII(d)
	if err != nil {
		return "", xerrors.Errorf("domain %q: %w", domain, err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	// A single label ("localhost", "internal") is not a public email domain.
	if !strings.Contains(ascii, ".") {
		return "", xerrors.Errorf("domain: %q has no public suffix", domain)
	}
	// Belt and braces: the A-label output must still be a plausible hostname.
	if net.ParseIP(ascii) != nil {
		return "", xerrors.Errorf("domain: %q resolves to an IP literal form", domain)
	}
	// Idempotence, verified rather than assumed. Some Punycode labels convert
	// once and then fail validation on their own output (an A-label whose
	// decoded form is invalid), which would make the accepted spelling depend
	// on how many times normalization ran. The domain is inside the kid
	// preimage, so two code paths disagreeing about its spelling would break
	// interoperability — reject instead, and let the one canonical spelling be
	// the only accepted one.
	stable, err := idnaProfile.ToASCII(ascii)
	if err != nil {
		return "", xerrors.Errorf("domain %q: unstable normalization: %w", domain, err)
	}
	if strings.ToLower(strings.TrimSuffix(stable, ".")) != ascii {
		return "", xerrors.Errorf("domain %q has no stable normal form (%q then %q)", domain, ascii, stable)
	}
	return ascii, nil
}

// DNSName is the TXT owner name that advertises MKDP1 for a domain.
func DNSName(domain string) (string, error) {
	d, err := Normalize(domain)
	if err != nil {
		return "", err
	}
	return mailkey.DNSPrefix + "." + d, nil
}

// AuthorityHost is the only host MKDP1 will talk to for a domain.
func AuthorityHost(domain string) (string, error) {
	d, err := Normalize(domain)
	if err != nil {
		return "", err
	}
	return mailkey.HostPrefix + "." + d, nil
}

// DiscoveryURL derives the complete authority URL. It takes a domain and
// nothing else: there is no code path in MKDP1 that accepts a caller-supplied
// URL, host or port.
func DiscoveryURL(domain string) (*url.URL, error) {
	host, err := AuthorityHost(domain)
	if err != nil {
		return nil, err
	}
	return &url.URL{Scheme: "https", Host: host, Path: mailkey.WellKnownPath}, nil
}

// ParseDNS reads the TXT strings at _mailkey.<domain> into advertisements.
// Malformed records are skipped (with the reason returned for diagnostics)
// rather than failing the set: one broken record must not hide a good one.
//
// Several DIFFERENT valid ids mean the DNS view is inconsistent — the caller
// records that and resolves over HTTPS. It does not pick a winner; there is no
// rule by which one unauthenticated record beats another.
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

// ParseHeader reads a Mail-Key header value. The header names its own domain
// (d=), which is normalized here; the authority host is then derived from it,
// never taken from the header.
func ParseHeader(headerValue string) (mailkey.Advertisement, error) {
	if len(headerValue) > MaxHeaderLen {
		return mailkey.Advertisement{}, xerrors.Errorf("header: longer than %d bytes", MaxHeaderLen)
	}
	return parseParams(headerValue, "", true)
}

// FormatHeader renders the header a server stamps on its own outbound mail.
func FormatHeader(domain string, id mailkey.ManifestID) (string, error) {
	d, err := Normalize(domain)
	if err != nil {
		return "", err
	}
	return "v=" + mailkey.Version + "; d=" + d + "; id=" + encodeID(id) + "; mode=" + mailkey.Mode, nil
}

// FormatDNS renders the TXT value a server publishes for its own domain.
func FormatDNS(id mailkey.ManifestID) string {
	return "v=" + mailkey.Version + "; id=" + encodeID(id) + "; mode=" + mailkey.Mode
}

// parseParams parses the shared "k=v; k=v" grammar. requireDomain marks the
// header form, where d= is mandatory; the DNS form takes its domain from the
// owner name that was queried.
//
// Unknown versions and modes are refused, not guessed at: a client that cannot
// name the semantics of an object must not act on it.
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
	if m, ok := fields["mode"]; ok && m != mailkey.Mode {
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
	// Reject any field that could name a target: MKDP1 derives the host.
	for _, forbidden := range []string{"url", "host", "port", "path", "endpoint", "pk", "key", "seq"} {
		if _, present := fields[forbidden]; present {
			return zero, xerrors.Errorf("advertisement: field %q is not part of MKDP1", forbidden)
		}
	}
	if idv, ok := fields["id"]; ok {
		id, err := decodeID(idv)
		if err != nil {
			return zero, xerrors.Errorf("advertisement: id: %w", err)
		}
		ad.ManifestID, ad.HasID = id, true
	}
	return ad, nil
}
