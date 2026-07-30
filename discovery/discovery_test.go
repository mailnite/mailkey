/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package discovery_test

import (
	"strings"
	"testing"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/manifest"
)

// TestNormalize is the security boundary test: everything an attacker might put
// in a d= field, and what must happen to it. The accept list is short on
// purpose — a domain, and nothing that could name a different target.
func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":     "example.com",
		"EXAMPLE.COM":     "example.com",
		"example.com.":    "example.com",
		"  example.com  ": "example.com",
		"sub.example.com": "sub.example.com",
		"пример.рф":       "xn--e1afmkfd.xn--p1ai", // IDNA A-label
	} {
		got, err := discovery.Normalize(in)
		if err != nil {
			t.Errorf("Normalize(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{
		"", " ", ".", "localhost", "internal", // no public suffix
		"127.0.0.1", "::1", "0.0.0.0", "10.0.0.1", // IP literals
		"[::1]", "[fe80::1]",
		"example.com:443", "example.com:25", // ports
		"https://example.com", "http://example.com/x", // URLs
		"example.com/path", "example.com?q=1", "example.com#f",
		"*.example.com", "*", // wildcards
		"user@example.com",              // address, not domain
		"exa mple.com", "example\n.com", // whitespace/control
		"example.com%00", "ex%41mple.com", // percent-encoding
		strings.Repeat("a", 300) + ".com", // too long
	} {
		if got, err := discovery.Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) must fail, got %q", bad, got)
		}
	}
}

// TestDerivedNames: the TXT name and the authority URL are functions of the
// domain alone. There is no input that changes the scheme, host shape, port or
// path — that property is what makes the resolver's target unforgeable.
func TestDerivedNames(t *testing.T) {
	name, err := discovery.DNSName("Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if name != "_mailkey.example.com" {
		t.Fatalf("DNSName = %q", name)
	}
	host, err := discovery.AuthorityHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if host != "mail.example.com" {
		t.Fatalf("AuthorityHost = %q", host)
	}
	u, err := discovery.DiscoveryURL("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://mail.example.com/.well-known/mail-key" {
		t.Fatalf("DiscoveryURL = %q", u.String())
	}
	if u.Scheme != "https" || u.Port() != "" || u.User != nil || u.RawQuery != "" {
		t.Fatalf("DiscoveryURL must be a bare https URL: %+v", u)
	}
	// A hostile "domain" cannot produce a URL at all.
	for _, bad := range []string{"evil.example:8080", "https://evil.example", "127.0.0.1", "*.example.com"} {
		if _, err := discovery.DiscoveryURL(bad); err == nil {
			t.Errorf("DiscoveryURL(%q) must fail", bad)
		}
	}
}

func testID(t *testing.T) mailkey.ManifestID {
	t.Helper()
	var id mailkey.ManifestID
	for i := range id {
		id[i] = byte(i)
	}
	return id
}

// TestHeaderRoundTrip: what we stamp is what we parse, and the domain in the
// header is normalized on the way in.
func TestHeaderRoundTrip(t *testing.T) {
	id := testID(t)
	h, err := discovery.FormatHeader("Example.COM", id)
	if err != nil {
		t.Fatal(err)
	}
	want := "v=MKDP1; d=example.com; id=" + manifest.EncodeID(id) + "; mode=https"
	if h != want {
		t.Fatalf("FormatHeader = %q, want %q", h, want)
	}
	ad, err := discovery.ParseHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Domain != "example.com" || !ad.HasID || ad.ManifestID != id || ad.Mode != mailkey.Mode {
		t.Fatalf("ParseHeader = %+v", ad)
	}
	// Tolerant of spacing and field order, since other implementations will
	// format differently.
	for _, variant := range []string{
		"v=MKDP1;d=example.com;id=" + manifest.EncodeID(id) + ";mode=https",
		"  mode=https ;  id=" + manifest.EncodeID(id) + " ; d=EXAMPLE.com ; v=MKDP1  ",
		"v=MKDP1; d=example.com", // id and mode are optional
	} {
		if _, err := discovery.ParseHeader(variant); err != nil {
			t.Errorf("ParseHeader(%q): %v", variant, err)
		}
	}
}

// TestHeaderRejects: a header is untrusted input from a stranger. Each case
// below is something a hostile sender could try.
func TestHeaderRejects(t *testing.T) {
	id := manifest.EncodeID(testID(t))
	for name, h := range map[string]string{
		"missing version":   "d=example.com; id=" + id,
		"unknown version":   "v=MKDP2; d=example.com; id=" + id,
		"unknown mode":      "v=MKDP1; d=example.com; mode=dns",
		"missing domain":    "v=MKDP1; id=" + id,
		"ip literal domain": "v=MKDP1; d=127.0.0.1",
		"domain with port":  "v=MKDP1; d=example.com:8080",
		"url as domain":     "v=MKDP1; d=https://evil.example/x",
		"carries a url":     "v=MKDP1; d=example.com; url=https://evil.example",
		"carries a host":    "v=MKDP1; d=example.com; host=evil.example",
		"carries a port":    "v=MKDP1; d=example.com; port=8080",
		"carries a key":     "v=MKDP1; d=example.com; pk=AAAA",
		"carries a seq":     "v=MKDP1; d=example.com; seq=999999",
		"padded id":         "v=MKDP1; d=example.com; id=" + id + "=",
		"short id":          "v=MKDP1; d=example.com; id=AAAA",
		"duplicate field":   "v=MKDP1; d=example.com; d=evil.example",
		"not key=value":     "v=MKDP1; garbage; d=example.com",
		"oversized":         "v=MKDP1; d=example.com; id=" + strings.Repeat("A", 600),
	} {
		if ad, err := discovery.ParseHeader(h); err == nil {
			t.Errorf("%s: must be refused, got %+v", name, ad)
		}
	}
}

// TestParseDNS: valid records parse, malformed ones are skipped rather than
// poisoning the set, and several different ids are reported as-is — there is no
// rule by which one unauthenticated record beats another.
func TestParseDNS(t *testing.T) {
	idA := testID(t)
	idB := idA
	idB[0] ^= 0xff

	ads, skipped, err := discovery.ParseDNS("example.com", []string{
		discovery.FormatDNS(idA),
		"v=spf1 include:_spf.example.com ~all", // an unrelated TXT record
		discovery.FormatDNS(idB),
		"v=MKDP1; id=broken",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ads) != 2 {
		t.Fatalf("want 2 advertisements, got %d", len(ads))
	}
	if len(skipped) != 2 {
		t.Fatalf("want 2 skipped records, got %d: %v", len(skipped), skipped)
	}
	if ads[0].ManifestID != idA || ads[1].ManifestID != idB {
		t.Fatal("advertisements must preserve the observed ids verbatim")
	}
	for _, ad := range ads {
		if ad.Domain != "example.com" {
			t.Fatalf("DNS advertisement domain must come from the owner name, got %q", ad.Domain)
		}
	}
	// A d= that contradicts the owner name is malformed, not an override.
	_, skipped, err = discovery.ParseDNS("example.com", []string{"v=MKDP1; d=evil.example; id=" + manifest.EncodeID(idA)})
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 {
		t.Fatal("a contradicting d= must be skipped")
	}
}
