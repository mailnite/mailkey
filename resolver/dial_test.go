/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package resolver_test

import (
	"net/netip"
	"testing"

	"github.com/mailnite/mailkey/resolver"
)

// TestAddressPolicyTable exercises the policy directly, address by address. The
// resolver tests prove it is wired into the dial path; this proves the table
// itself, including the ranges that no reasonable test environment can produce.
func TestAddressPolicyTable(t *testing.T) {
	strict := resolver.AddressPolicy{}
	permissive := resolver.AddressPolicy{AllowPrivate: true}

	// Public unicast: permitted by both.
	for _, ok := range []string{"93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "2001:4860:4860::8888"} {
		a := netip.MustParseAddr(ok)
		if err := strict.Permit(a); err != nil {
			t.Errorf("strict must permit public %s: %v", ok, err)
		}
		if err := permissive.Permit(a); err != nil {
			t.Errorf("permissive must permit public %s: %v", ok, err)
		}
	}

	// Refused by the default policy; permitted only under the opt-in.
	for _, priv := range []string{
		"127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.5.5", "192.168.0.1", "::1", "fd12::1",
	} {
		a := netip.MustParseAddr(priv)
		if err := strict.Permit(a); err == nil {
			t.Errorf("strict must refuse %s", priv)
		}
		if err := permissive.Permit(a); err != nil {
			t.Errorf("the opt-in must permit %s: %v", priv, err)
		}
	}

	// Refused by BOTH: metadata/link-local, non-unicast, and the reserved
	// special-purpose ranges. Nothing here is ever a mail authority, so the
	// opt-in deliberately does not reach them.
	for _, never := range []string{
		"169.254.169.254", // cloud metadata — the SSRF prize
		"169.254.1.1", "fe80::1", "ff02::1",
		"0.0.0.0", "::", "239.1.2.3", "224.0.0.1",
		"100.64.0.1",   // CGNAT
		"192.0.2.1",    // TEST-NET-1
		"198.51.100.1", // TEST-NET-2
		"203.0.113.1",  // TEST-NET-3
		"198.19.0.1",   // benchmarking
		"192.0.0.1",    // protocol assignments
		"240.0.0.1",    // reserved
		"255.255.255.255",
		"2001:db8::1",            // documentation
		"64:ff9b::1",             // NAT64
		"::ffff:169.254.169.254", // the mapped form of the metadata address
	} {
		a := netip.MustParseAddr(never)
		if err := strict.Permit(a); err == nil {
			t.Errorf("strict must refuse %s", never)
		}
		if err := permissive.Permit(a); err == nil {
			t.Errorf("even the opt-in must refuse %s", never)
		}
	}

	// An IPv4-mapped IPv6 address is judged as the IPv4 address it is —
	// otherwise every rule above could be bypassed by writing ::ffff:.
	if err := strict.Permit(netip.MustParseAddr("::ffff:127.0.0.1")); err == nil {
		t.Error("strict must refuse the mapped form of loopback")
	}
	if err := strict.Permit(netip.MustParseAddr("::ffff:10.0.0.1")); err == nil {
		t.Error("strict must refuse the mapped form of a private address")
	}
	// The zero Addr is not a destination.
	if err := strict.Permit(netip.Addr{}); err == nil {
		t.Error("an invalid address must be refused")
	}
}
