/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package resolver

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/mailnite/mailkey"
	"golang.org/x/xerrors"
)

// AddressPolicy decides which destination addresses MKDP1 may connect to.
//
// This is the anti-SSRF core, and it exists because a stranger's email can
// trigger a fetch: the domain part is attacker-influenced, so the ADDRESS it
// resolves to must be checked before we connect to it. Public unicast only, by
// default — anything that could reach infrastructure behind the mail server is
// refused.
type AddressPolicy struct {
	// AllowPrivate permits loopback, private and link-local destinations. Off
	// by default. A private Mailnite deployment behind split DNS must opt in
	// deliberately; the setting exists so that choice is visible in
	// configuration instead of hidden in code.
	AllowPrivate bool
}

// Permit reports whether an address may be dialed, and why not when it may not.
//
// The check runs on EVERY address for EVERY connection — that is what makes it
// a DNS-rebinding defense rather than a one-time validation: an authority whose
// name resolved publicly a moment ago cannot answer 127.0.0.1 on the next
// lookup and be dialed anyway.
func (p AddressPolicy) Permit(addr netip.Addr) error {
	if !addr.IsValid() {
		return xerrors.New("invalid address")
	}
	// An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be judged as the
	// IPv4 address it really is, or every rule below could be bypassed by
	// writing the mapped form.
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	// Refused in BOTH modes. Nothing here has ever been a mail authority, and
	// the first entries are the ones that make SSRF worth attempting: link-local
	// carries the cloud metadata services (169.254.169.254 and friends).
	switch {
	case addr.IsUnspecified():
		return xerrors.Errorf("address %s is unspecified", addr)
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return xerrors.Errorf("address %s is multicast", addr)
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return xerrors.Errorf("address %s is link-local (metadata services are never MKDP1 authorities)", addr)
	}
	for _, r := range reservedRanges {
		if r.Contains(addr) {
			return xerrors.Errorf("address %s is in the reserved range %s", addr, r)
		}
	}

	// Refused unless a deployment opted in: the ranges a split-DNS Mailnite
	// might legitimately publish its own authority on.
	if !p.AllowPrivate {
		switch {
		case addr.IsLoopback():
			return xerrors.Errorf("address %s is loopback", addr)
		case addr.IsPrivate():
			return xerrors.Errorf("address %s is in a private range", addr)
		}
		for _, r := range privateRanges {
			if r.Contains(addr) {
				return xerrors.Errorf("address %s is in the private range %s", addr, r)
			}
		}
	}
	return nil
}

// reservedRanges are special-purpose prefixes refused regardless of the opt-in:
// carrier NAT and test networks (which reach shared infrastructure), IPv6
// documentation space, and the translation prefixes that can smuggle an IPv4
// destination past an address check.
var reservedRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64
	netip.MustParsePrefix("100::/64"),      // discard-only
	netip.MustParsePrefix("2001:db8::/32"), // documentation
}

// privateRanges are the prefixes the AllowPrivate opt-in widens to, beyond what
// netip's own loopback and private predicates already cover.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("fc00::/7"), // IPv6 unique-local
}

// LookupFunc resolves a hostname to addresses. It is the resolver's ONLY
// injection seam for name resolution: substituting it cannot weaken the address
// policy, because the policy runs on whatever it returns.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// systemLookup resolves through the process resolver.
func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// dialer connects to the MKDP1 authority: it resolves the host through the
// lookup seam, filters every candidate address through the policy, and dials
// the permitted ones on the fixed port. The port comes from here, not from the
// request, so no input can retarget it.
type dialer struct {
	policy  AddressPolicy
	lookup  LookupFunc
	port    string
	timeout time.Duration
	domain  string // for error attribution
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, mailkey.Fail(mailkey.FailurePolicy, d.domain, err)
	}
	// The transport should never ask for another port; refuse if it somehow
	// does rather than trusting the caller chain.
	if port != d.port {
		return nil, mailkey.Failf(mailkey.FailurePolicy, d.domain,
			"MKDP1 connects only to port %s, not %s", d.port, port)
	}
	// A literal address still goes through the policy — there is no path that
	// skips the check.
	var addrs []netip.Addr
	if lit, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{lit}
	} else {
		addrs, err = d.lookup(ctx, host)
		if err != nil {
			return nil, mailkey.Fail(mailkey.FailureNetwork, d.domain, err)
		}
	}
	if len(addrs) == 0 {
		return nil, mailkey.Failf(mailkey.FailureNetwork, d.domain, "no addresses for %s", host)
	}
	var refused error
	var lastDial error
	for _, a := range addrs {
		if perr := d.policy.Permit(a); perr != nil {
			if refused == nil {
				refused = perr
			}
			continue
		}
		nd := net.Dialer{Timeout: d.timeout}
		conn, derr := nd.DialContext(ctx, network, net.JoinHostPort(a.String(), d.port))
		if derr == nil {
			return conn, nil
		}
		lastDial = derr
	}
	if lastDial != nil {
		return nil, mailkey.Fail(mailkey.FailureNetwork, d.domain, lastDial)
	}
	// Every candidate was refused by policy: the authority resolves somewhere
	// we will not talk to. Reported as policy, not network, so a caller can
	// tell "unreachable" from "we declined".
	return nil, mailkey.Failf(mailkey.FailurePolicy, d.domain,
		"the authority for %s resolves to no permitted address: %v", host, refused)
}
