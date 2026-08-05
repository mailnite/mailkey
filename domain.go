/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package mailkey

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/xerrors"
)

// maxDomainNameLen is the DNS limit on a presentation-format name.
const maxDomainNameLen = 253

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
func NormalizeDomain(domain string) (string, error) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return "", xerrors.New("domain: empty")
	}
	if len(d) > maxDomainNameLen+1 { // +1 tolerates a trailing dot before trimming
		return "", xerrors.Errorf("domain: longer than %d characters", maxDomainNameLen)
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
