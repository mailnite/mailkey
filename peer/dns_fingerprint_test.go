/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/peer"
)

// TestDNSFingerprintPrecedesFirstContact is the C-04 regression. The DNS fp
// must be durable before the fetch it triggers can make a first-contact pinning
// decision; otherwise the decision matrix has a DNS input that production never
// supplies and a TLS-path attacker can install the first pin unopposed.
func TestDNSFingerprintPrecedesFirstContact(t *testing.T) {
	for _, tc := range []struct {
		name       string
		dnsSeed    byte
		wantStatus mailkey.IdentityStatus
		wantPinned bool
	}{
		{name: "matching DNS corroborates the first pin", dnsSeed: 1, wantStatus: mailkey.IdentityPinned, wantPinned: true},
		{name: "mismatching DNS withholds the first pin", dnsSeed: 9, wantStatus: mailkey.IdentityContested},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(1_750_000_000, 0).UTC()
			svc, resolver, store := newSvc(t, &clock)
			ctx := context.Background()

			fetched := result(t, domain, clock, 1)
			dnsFP, _, _ := fpFor(t, domain, tc.dnsSeed)
			resolver.set(fetched, nil)
			block := make(chan struct{})
			resolver.block = block
			released := false
			t.Cleanup(func() {
				if !released {
					close(block)
				}
			})

			// FormatDNS emits the current fp-only record. In particular, absence
			// of the deprecated id must not make this observation inconsistent.
			if err := svc.ObserveDNS(ctx, domain, []string{
				discovery.FormatDNS(dnsFP, true, mailkey.ManifestID{}, ""),
			}); err != nil {
				t.Fatal(err)
			}

			// The resolver is still blocked. Seeing fp here proves persistence
			// precedes scheduling/fetch completion rather than racing behind it.
			before, err := store.GetPeer(ctx, domain)
			if err != nil || before == nil {
				t.Fatalf("DNS observation was not stored: %v", err)
			}
			if !before.Identity.HasDNSFP || before.Identity.DNSFingerprint != dnsFP {
				t.Fatalf("DNS fingerprint did not reach identity state: %+v", before.Identity)
			}
			if !before.Identity.DNSObservedAt.Equal(clock) {
				t.Fatalf("DNS observation time = %s, want %s", before.Identity.DNSObservedAt, clock)
			}
			if len(before.Observations) != 1 || before.Observations[0].Status == mailkey.ObservationInconsistent {
				t.Fatalf("fp-only record was not retained as a valid observation: %+v", before.Observations)
			}

			close(block)
			released = true
			deadline := time.Now().Add(2 * time.Second)
			var after *mailkey.Peer
			for time.Now().Before(deadline) {
				after, err = store.GetPeer(ctx, domain)
				if err != nil {
					t.Fatal(err)
				}
				if after != nil && after.Effective != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if after == nil || after.Effective == nil {
				t.Fatal("the DNS-triggered fetch did not complete")
			}
			if after.Identity.Status != tc.wantStatus {
				t.Fatalf("identity status = %q, want %q", after.Identity.Status, tc.wantStatus)
			}
			if got := after.Identity.Status == mailkey.IdentityPinned; got != tc.wantPinned {
				t.Fatalf("pinned = %v, want %v", got, tc.wantPinned)
			}
			if tc.wantPinned && after.Identity.Fingerprint != fetched.Proof.Fingerprint {
				t.Fatal("matching DNS did not establish the fetched signer as the pin")
			}
			if !tc.wantPinned && after.Identity.Fingerprint != (mailkey.Fingerprint{}) {
				t.Fatal("DNS disagreement installed a first-contact pin")
			}
		})
	}
}

// TestDNSFingerprintChangesBypassAdmission ensures the write-flood guard does
// not mistake an identity rollover for a repeat merely because it arrived
// inside the coalescing interval. It also pins the fail-safe rule: a conflicting
// or absent current answer cannot erase the last agreed fingerprint.
func TestDNSFingerprintChangesBypassAdmission(t *testing.T) {
	clock := time.Unix(1_750_000_000, 0).UTC()
	now := func() time.Time { return clock }
	store := newCounting(now)
	svc := peer.NewService(
		&fakeResolver{err: mailkey.Failf(mailkey.FailureNetwork, "resolve", "offline")},
		store,
		peer.Options{Now: now, Workers: 1, QueueSize: 4},
	)
	defer svc.Close()
	ctx := context.Background()
	fp1, _, _ := fpFor(t, domain, 1)
	fp2, _, _ := fpFor(t, domain, 2)
	fp3, _, _ := fpFor(t, domain, 3)

	if err := svc.ObserveDNS(ctx, domain, []string{discovery.FormatDNS(fp1, true, mailkey.ManifestID{}, "")}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ObserveDNS(ctx, domain, []string{discovery.FormatDNS(fp2, true, mailkey.ManifestID{}, "")}); err != nil {
		t.Fatal(err)
	}
	if got := store.writes.Load(); got != 2 {
		t.Fatalf("a changed DNS fp inside the admission interval wrote %d observations, want 2", got)
	}
	p, _ := store.GetPeer(ctx, domain)
	if p == nil || !p.Identity.HasDNSFP || p.Identity.DNSFingerprint != fp2 {
		t.Fatalf("latest agreed DNS fingerprint was not stored: %+v", p)
	}

	if err := svc.ObserveDNS(ctx, domain, []string{
		discovery.FormatDNS(fp1, true, mailkey.ManifestID{}, ""),
		discovery.FormatDNS(fp3, true, mailkey.ManifestID{}, ""),
	}); err != nil {
		t.Fatal(err)
	}
	p, _ = store.GetPeer(ctx, domain)
	if p.Identity.DNSFingerprint != fp2 || !p.Identity.HasDNSFP {
		t.Fatal("a conflicting DNS answer erased the last agreed fingerprint")
	}
	if len(p.Observations) != 1 || p.Observations[0].Status != mailkey.ObservationInconsistent ||
		!strings.Contains(p.Observations[0].Context, "identity fingerprints") {
		t.Fatalf("conflicting fingerprints were not diagnosed: %+v", p.Observations)
	}

	legacyID := anyID(7)
	if err := svc.ObserveDNS(ctx, domain, []string{
		discovery.FormatDNS(mailkey.Fingerprint{}, false, legacyID, ""),
	}); err != nil {
		t.Fatal(err)
	}
	p, _ = store.GetPeer(ctx, domain)
	if p.Identity.DNSFingerprint != fp2 || !p.Identity.HasDNSFP {
		t.Fatal("a legacy id-only answer erased established DNS corroboration")
	}
}
