/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/peer"
)

// routingTrap models the C-03 attacker. It can return a fully consistent,
// attacker-signed manifest for the victim only when the untrusted a= routed the
// request to the attacker's authority. The subject-domain endpoint is absent.
type routingTrap struct {
	attacker string
	result   mailkey.Result
	calls    chan string
}

func (r *routingTrap) Resolve(_ context.Context, domain, authority string) (mailkey.Result, error) {
	r.calls <- authority
	if authority == r.attacker {
		return r.result, nil
	}
	return mailkey.Result{}, mailkey.Fail(mailkey.FailureAbsent, domain, errors.New("subject endpoint absent"))
}

func delegatedResult(t *testing.T, domain, authority string, now time.Time, signerSeed byte) mailkey.Result {
	t.Helper()
	res := realResult(t, domain, now, signerSeed)
	res.Manifest.Authority = []string{authority}
	raw, err := manifest.Pack(res.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	res.Raw = raw
	res.ManifestID = manifest.ManifestIDOf(raw)
	fp, pk, priv := fpFor(t, domain, signerSeed)
	sig, err := identity.SignManifest(priv, domain, raw)
	if err != nil {
		t.Fatal(err)
	}
	res.Proof = &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}
	return res
}

// TestUntrustedDelegationCannotRouteFirstContact is the end-to-end C-03
// regression. Both supported observation channels are untrusted at bootstrap:
// they may advertise a= and trigger discovery, but the first request must still
// go to mail.<subject>. Under the vulnerable behavior this test routes to the
// attacker, accepts its self-introduced identity, and leaves a permanent pin.
func TestUntrustedDelegationCannotRouteFirstContact(t *testing.T) {
	const (
		domain   = "victim.example"
		attacker = "attacker.example"
	)
	now := time.Unix(1_750_000_000, 0).UTC()
	malicious := delegatedResult(t, domain, attacker, now, 9)

	for _, tc := range []struct {
		name    string
		observe func(*peer.Service) error
	}{
		{
			name: "inbound header",
			observe: func(s *peer.Service) error {
				h, err := discovery.FormatHeader(domain, malicious.ManifestID, attacker)
				if err != nil {
					return err
				}
				return s.ObserveHeader(context.Background(), h, "attacker-controlled inbound mail")
			},
		},
		{
			name: "unauthenticated DNS observation",
			observe: func(s *peer.Service) error {
				txt := discovery.FormatDNS(mailkey.Fingerprint{}, false, malicious.ManifestID, attacker)
				return s.ObserveDNS(context.Background(), domain, []string{txt})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := peer.NewMemStore(func() time.Time { return now })
			r := &routingTrap{
				attacker: attacker,
				result:   malicious,
				calls:    make(chan string, 2),
			}
			svc := peer.NewService(r, store, peer.Options{
				Now: func() time.Time { return now }, Workers: 1, QueueSize: 1,
			})

			if err := tc.observe(svc); err != nil {
				t.Fatal(err)
			}
			select {
			case authority := <-r.calls:
				if authority != "" {
					t.Fatalf("untrusted first contact routed to %q", authority)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("observation did not trigger resolution")
			}
			svc.Close() // wait until the asynchronous failure is persisted

			p, err := store.GetPeer(ctx, domain)
			if err != nil || p == nil {
				t.Fatalf("observation was not retained: peer=%+v err=%v", p, err)
			}
			if p.Effective != nil || p.Identity.Status == mailkey.IdentityPinned {
				t.Fatalf("attacker-selected authority established trust: %+v", p)
			}
			found := false
			for _, o := range p.Observations {
				if o.Authority == attacker {
					found = true
				}
			}
			if !found {
				t.Fatal("rejected routing claim was not retained for diagnostics")
			}
		})
	}
}

// TestPinnedIdentityMayUseObservedDelegation preserves the safe half of the
// feature. Once a pin exists, a= may route the request because a response from
// that host still cannot replace the established signer.
func TestPinnedIdentityMayUseObservedDelegation(t *testing.T) {
	const (
		domain   = "customer.example"
		provider = "provider.example"
	)
	now := time.Unix(1_750_000_000, 0).UTC()
	legitimate := delegatedResult(t, domain, provider, now, 1)
	fp, pk, _ := fpFor(t, domain, 1)
	ctx := context.Background()
	store := peer.NewMemStore(func() time.Time { return now })
	if err := store.SetIdentity(ctx, domain, mailkey.IdentityState{
		Status: mailkey.IdentityPinned, Fingerprint: fp,
		PinnedPublicKey: append([]byte(nil), pk...), EverHTTPSValidated: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutObservation(ctx, domain, mailkey.Observation{
		Source: mailkey.SourceHeader, Authority: provider, ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	r := &routingTrap{attacker: provider, result: legitimate, calls: make(chan string, 1)}
	svc := peer.NewService(r, store, peer.Options{Now: func() time.Time { return now }})
	t.Cleanup(svc.Close)

	p, err := svc.Refresh(ctx, domain)
	if err != nil {
		t.Fatalf("pinned delegated refresh failed: %v", err)
	}
	if authority := <-r.calls; authority != provider {
		t.Fatalf("pinned delegation routed to %q, want %q", authority, provider)
	}
	if p.Effective == nil || p.Effective.ManifestID != legitimate.ManifestID ||
		p.Identity.Fingerprint != fp {
		t.Fatalf("pinned delegated response was not installed under the existing pin: %+v", p)
	}
}
