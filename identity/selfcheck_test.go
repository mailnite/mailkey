/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity_test

import (
	"testing"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
)

func fps(t *testing.T, n int) []mailkey.Fingerprint {
	t.Helper()
	out := make([]mailkey.Fingerprint, n)
	for i := range out {
		_, _, fp := keypair(t)
		out[i] = fp
	}
	return out
}

func has(r identity.SelfCheckResult, f identity.SelfCheckFinding) bool {
	for _, x := range r.Findings {
		if x == f {
			return true
		}
	}
	return false
}

// The healthy case: four values agreeing, DNSSEC validated, nothing to report.
func TestAgreementIsSilent(t *testing.T) {
	f := fps(t, 1)[0]
	r := identity.SelfCheck(identity.SelfCheckInput{
		Configured: f, Served: f, External: f, DNS: f, HasDNS: true, DNSSECValidated: true,
	})
	if len(r.Findings) != 0 || !r.OK {
		t.Fatalf("a healthy publisher reported %v", r.Findings)
	}
}

/*
TestEachPairFailsSeparately is why there are four values and not two.

Comparing only the ends would say "something is wrong" and nothing about where,
which for an operator at 3am is barely better than hearing it from a
correspondent.
*/
func TestEachPairFailsSeparately(t *testing.T) {
	f := fps(t, 2)
	good, other := f[0], f[1]

	// A deployment that half-applied.
	r := identity.SelfCheck(identity.SelfCheckInput{
		Configured: good, Served: other, External: other, DNS: other, HasDNS: true, DNSSECValidated: true,
	})
	if !has(r, identity.SelfCheckServedMismatch) {
		t.Fatalf("configured≠served not reported: %v", r.Findings)
	}
	if has(r, identity.SelfCheckExternalMismatch) {
		t.Fatal("a faithful proxy in front of a wrong server was reported as a second fault")
	}

	// Something in front of the server.
	r = identity.SelfCheck(identity.SelfCheckInput{
		Configured: good, Served: good, External: other, DNS: good, HasDNS: true, DNSSECValidated: true,
	})
	if !has(r, identity.SelfCheckExternalMismatch) {
		t.Fatalf("served≠external not reported: %v", r.Findings)
	}
	if has(r, identity.SelfCheckServedMismatch) {
		t.Fatal("an interception was blamed on the local configuration")
	}
}

/*
TestDNSCannotVetoARotation.

DNS is corroboration, never authority (§7). A DNS disagreement withholds pins
and is worth showing — but if it BLOCKED activation, anyone able to disturb a
domain's DNS would hold a veto over its key management, which is a larger power
than the corroboration is worth.
*/
func TestDNSCannotVetoARotation(t *testing.T) {
	f := fps(t, 2)
	good, other := f[0], f[1]
	r := identity.SelfCheck(identity.SelfCheckInput{
		Configured: good, Served: good, External: good, DNS: other, HasDNS: true, DNSSECValidated: true,
	})
	if !has(r, identity.SelfCheckDNSMismatch) {
		t.Fatalf("a DNS disagreement was not reported: %v", r.Findings)
	}
	if r.Blocked() || !r.OK {
		t.Fatal("DNS blocked an activation — anyone who can disturb DNS would hold a veto over key management")
	}
}

// Absent DNS is not an error: §7 makes it optional. It is still shown, because
// it is the difference between a sender pinning on first contact and merely
// encrypting.
func TestAbsentDNSIsShownButNotBlocking(t *testing.T) {
	f := fps(t, 1)[0]
	r := identity.SelfCheck(identity.SelfCheckInput{Configured: f, Served: f, External: f})
	if !has(r, identity.SelfCheckDNSAbsent) {
		t.Fatalf("absent DNS was not shown: %v", r.Findings)
	}
	if r.Blocked() {
		t.Fatal("a domain without a DNS advertisement could not activate an identity")
	}
}

/*
TestActivationIsBlockedWhenTheWorldCannotSeeIt.

§9 runs the check BEFORE activating. Activating over an unreachable or
disagreeing external view publishes an identity correspondents cannot fetch —
and every one of them that tries during the window either fails to pin or pins
something else.
*/
func TestActivationIsBlockedWhenTheWorldCannotSeeIt(t *testing.T) {
	f := fps(t, 1)[0]
	for name, in := range map[string]identity.SelfCheckInput{
		"not serving at all":    {Configured: f},
		"external unreachable":  {Configured: f, Served: f},
		"served but not itself": {Configured: f, Served: fps(t, 1)[0], External: f},
	} {
		t.Run(name, func(t *testing.T) {
			if r := identity.SelfCheck(in); !r.Blocked() || r.OK {
				t.Fatalf("activation was allowed with %v", r.Findings)
			}
		})
	}
}
