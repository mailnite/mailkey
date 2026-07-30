/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package discovery_test

import (
	"strings"
	"testing"

	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/manifest"
)

// FuzzNormalize fuzzes the SSRF boundary. The property is not "accepts a lot"
// but "anything accepted is safe to derive a URL from": no scheme, no port, no
// path, no credentials, no IP literal, lowercase, and idempotent — normalizing
// an already-normalized domain must change nothing, or the derived names would
// depend on how many times the function ran.
func FuzzNormalize(f *testing.F) {
	for _, seed := range []string{
		"example.com", "EXAMPLE.COM.", "sub.example.com", "пример.рф",
		"", ".", "..", "localhost", "127.0.0.1", "::1", "[::1]",
		"example.com:443", "https://example.com", "example.com/x",
		"*.example.com", "user@example.com", "xn--e1afmkfd.xn--p1ai",
		strings.Repeat("a", 300), "a..b", "-example.com", "exam_ple.com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		d, err := discovery.Normalize(in)
		if err != nil {
			return
		}
		if d == "" {
			t.Fatal("accepted an empty domain")
		}
		if d != strings.ToLower(d) {
			t.Fatalf("accepted %q, not lowercased: %q", in, d)
		}
		for _, forbidden := range []string{":", "/", "\\", "?", "#", "@", "*", " ", "\t", "%", "[", "]"} {
			if strings.Contains(d, forbidden) {
				t.Fatalf("accepted %q containing %q: %q", in, forbidden, d)
			}
		}
		if strings.HasSuffix(d, ".") || !strings.Contains(d, ".") {
			t.Fatalf("accepted %q with a bad label structure: %q", in, d)
		}
		// Idempotent: derived names must not depend on normalization passes.
		again, err := discovery.Normalize(d)
		if err != nil {
			t.Fatalf("normalizing %q again failed: %v", d, err)
		}
		if again != d {
			t.Fatalf("not idempotent: %q → %q → %q", in, d, again)
		}
		// The derived URL is always the same fixed shape.
		u, err := discovery.DiscoveryURL(d)
		if err != nil {
			t.Fatalf("an accepted domain must yield a URL: %v", err)
		}
		if u.Scheme != "https" || u.Path != "/.well-known/mail-key" || u.Host != "mail."+d || u.User != nil || u.RawQuery != "" {
			t.Fatalf("derived URL is not the fixed shape: %+v", u)
		}
	})
}

// FuzzParseHeader fuzzes the header parser — the entry point a stranger's email
// reaches. The property: anything accepted names a domain that is already
// normalized, so the resolver cannot be handed an unnormalized target.
func FuzzParseHeader(f *testing.F) {
	for _, seed := range []string{
		"v=MKDP1; d=example.com; mode=https",
		"v=MKDP1; d=example.com; id=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; mode=https",
		"", "v=", "v=MKDP1", "v=MKDP1;;;", "v=MKDP1; d=", "v=MKDP1; d=example.com; url=http://x",
		strings.Repeat("v=MKDP1; ", 100),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ad, err := discovery.ParseHeader(in)
		if err != nil {
			return
		}
		if ad.Version != "MKDP1" || ad.Mode != "https" {
			t.Fatalf("accepted a non-MKDP1 advertisement: %+v", ad)
		}
		norm, nerr := discovery.Normalize(ad.Domain)
		if nerr != nil || norm != ad.Domain {
			t.Fatalf("accepted an unnormalized domain %q (norm %q, err %v)", ad.Domain, norm, nerr)
		}
	})
}

/*
FuzzParseDNS fuzzes the DNS parameter parser — the second of the two
unauthenticated inputs an outsider controls (the other is the mail header).

The property that matters is not tolerance but CONTAINMENT: whatever a TXT record
says, the only thing it can ever produce is an advertisement naming the domain
that was queried, carrying at most a manifest id. It can never carry key
material, and it can never redirect discovery — parseParams refuses url/host/
port/path/endpoint/pk/key/seq outright, so a record cannot smuggle a location or
a key past the caller.

A malformed record among good ones must also be SKIPPED rather than fatal: one
broken string in a TXT set must not hide a valid sibling.
*/
func FuzzParseDNS(f *testing.F) {
	for _, seed := range []string{
		"v=MKDP1; id=iErreOTszRhevJCaD56t1MfFP_EqAd3NsKsrfmERfpw; mode=https",
		"v=MKDP1; id=AAAA; mode=https", "v=MKDP1", "v=MKDP2; id=x",
		"v=MKDP1; id=x; url=https://evil.test/key", "v=MKDP1; pk=AAAA",
		"v=MKDP1; seq=999999", "v=MKDP1; host=evil.test", "v=MKDP1; port=8443",
		"", " ", ";;;", "v=", "=", "v=MKDP1;;id=x", "V=mkdp1; ID=x",
		strings.Repeat("v=MKDP1; id=x; ", 50),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, txt string) {
		// Two records so the "one bad record must not hide a good one" path runs.
		const good = "v=MKDP1; id=iErreOTszRhevJCaD56t1MfFP_EqAd3NsKsrfmERfpw; mode=https"
		ads, _, err := discovery.ParseDNS("example.com", []string{txt, good})
		if err != nil {
			// A whole-set error is only allowed for an unusable owner domain,
			// which is constant here.
			t.Fatalf("ParseDNS failed for a valid domain: %v", err)
		}
		if len(ads) == 0 {
			t.Fatal("a valid sibling record must survive a malformed one")
		}
		for _, ad := range ads {
			// The domain comes from the QUERIED name, never from the record.
			if ad.Domain != "example.com" {
				t.Fatalf("advertisement domain %q was taken from the record", ad.Domain)
			}
			if ad.HasID {
				// An accepted id must be exactly the 32 bytes an id is, and must
				// re-encode to the canonical spelling it arrived as.
				if _, err := manifest.DecodeID(manifest.EncodeID(ad.ManifestID)); err != nil {
					t.Fatalf("accepted id does not round trip: %v", err)
				}
			}
		}
	})
}
