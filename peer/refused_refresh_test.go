/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"context"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/peer"
)

/*
TestRefusedRefreshUsesTheTrustedCache is the service-level regression for C-01.

The identity matrix has always said "refuse this response, use the cache" when
a pinned domain's proof is stripped or changes signer while the old manifest is
still usable. The old service collapsed those two decisions into Verdict.Encrypt:
true and installed the response it had just refused.

Both attack shapes are exercised through Refresh, past the pure matrix and into
the store. The trusted object must remain effective, the refused object must not
appear even in history, and its issue time must not advance the replay watermark.
*/
func TestRefusedRefreshUsesTheTrustedCache(t *testing.T) {
	const dom = "example.com"
	now := time.Unix(1_750_000_000, 0).UTC()
	trusted := realResult(t, dom, now.Add(-time.Hour), 1)

	stripped := realResult(t, dom, now, 1)
	stripped.Proof = nil

	for _, tc := range []struct {
		name      string
		fresh     mailkey.Result
		issueCode mailkey.IssueCode
	}{
		{name: "proof stripped", fresh: stripped, issueCode: mailkey.IssueProofMissing},
		{name: "different signer", fresh: realResult(t, dom, now, 9), issueCode: mailkey.IssueSignerChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fp, pk, _ := fpFor(t, dom, 1)
			store := peer.NewMemStore(func() time.Time { return now })
			if err := store.InstallManifest(ctx, dom, trusted); err != nil {
				t.Fatal(err)
			}
			if err := store.SetIdentity(ctx, dom, mailkey.IdentityState{
				Status:                 mailkey.IdentityPinned,
				Fingerprint:            fp,
				PinnedPublicKey:        append([]byte(nil), pk...),
				EverHTTPSValidated:     true,
				LastVerifiedIssuedAt:   trusted.Manifest.IssuedAt,
				LastVerifiedManifestID: trusted.ManifestID,
			}); err != nil {
				t.Fatal(err)
			}

			svc := peer.NewService(&fixedResolver{res: tc.fresh}, store, peer.Options{
				Now: func() time.Time { return now },
			})
			t.Cleanup(svc.Close)

			got, err := svc.Refresh(ctx, dom)
			if err != nil {
				t.Fatalf("a usable trusted cache should keep encryption available: %v", err)
			}
			if got.Effective == nil || got.Effective.ManifestID != trusted.ManifestID {
				t.Fatalf("refused response replaced the trusted cache: effective=%+v", got.Effective)
			}
			for _, h := range got.History {
				if h.ManifestID == tc.fresh.ManifestID {
					t.Fatal("refused response was installed into manifest history")
				}
			}
			if got.Identity.LastVerifiedManifestID != trusted.ManifestID ||
				!got.Identity.LastVerifiedIssuedAt.Equal(trusted.Manifest.IssuedAt) {
				t.Fatalf("refused response advanced the replay watermark: %+v", got.Identity)
			}
			foundIssue := false
			for _, issue := range got.Issues {
				if issue.Code == tc.issueCode {
					foundIssue = true
				}
			}
			if !foundIssue {
				t.Fatalf("refusal was not recorded as %s: %+v", tc.issueCode, got.Issues)
			}

			res, err := svc.ResolveForEncryption(ctx, dom)
			if err != nil {
				t.Fatalf("the next send did not use the trusted cache: %v", err)
			}
			if res.ManifestID != trusted.ManifestID {
				t.Fatalf("next send selected %x, want trusted %x", res.ManifestID, trusted.ManifestID)
			}
		})
	}
}

// TestSameIssuedConflictNeverReplacesCache exercises C-02 through the complete
// service/store path. The conflicting manifest is validly signed by the pin, so
// identity authentication succeeds; its ambiguous ordering must still keep it
// out of effective and historical state.
func TestSameIssuedConflictNeverReplacesCache(t *testing.T) {
	const dom = "example.com"
	now := time.Unix(1_750_000_000, 0).UTC()
	trusted := realResult(t, dom, now, 1)
	conflict := realResult(t, dom, now, 9) // different receiver key, same issue time
	fp, pk, priv := fpFor(t, dom, 1)
	sig, err := identity.SignManifest(priv, dom, conflict.Raw)
	if err != nil {
		t.Fatal(err)
	}
	conflict.Proof = &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}
	if conflict.ManifestID == trusted.ManifestID {
		t.Fatal("test fixture did not produce distinct manifests")
	}

	ctx := context.Background()
	store := peer.NewMemStore(func() time.Time { return now })
	if err := store.InstallManifest(ctx, dom, trusted); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIdentity(ctx, dom, mailkey.IdentityState{
		Status:                 mailkey.IdentityPinned,
		Fingerprint:            fp,
		PinnedPublicKey:        append([]byte(nil), pk...),
		EverHTTPSValidated:     true,
		LastVerifiedIssuedAt:   trusted.Manifest.IssuedAt,
		LastVerifiedManifestID: trusted.ManifestID,
	}); err != nil {
		t.Fatal(err)
	}

	svc := peer.NewService(&fixedResolver{res: conflict}, store, peer.Options{
		Now: func() time.Time { return now },
	})
	t.Cleanup(svc.Close)

	got, err := svc.Refresh(ctx, dom)
	if err != nil {
		t.Fatalf("the trusted cache should remain usable: %v", err)
	}
	if got.Effective == nil || got.Effective.ManifestID != trusted.ManifestID {
		t.Fatalf("same-issued conflict replaced the trusted cache: %+v", got.Effective)
	}
	if got.Identity.LastVerifiedManifestID != trusted.ManifestID {
		t.Fatalf("same-issued conflict replaced the replay watermark: %+v", got.Identity)
	}
	for _, h := range got.History {
		if h.ManifestID == conflict.ManifestID {
			t.Fatal("same-issued conflict was installed into history")
		}
	}
	foundReplay := false
	for _, issue := range got.Issues {
		if issue.Code == mailkey.IssueReplay {
			foundReplay = true
		}
	}
	if !foundReplay {
		t.Fatalf("same-issued conflict raised no replay issue: %+v", got.Issues)
	}
}
