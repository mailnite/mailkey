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
	"github.com/mailnite/mailkey/peer"
)

// durabilityStore injects failures at the two trust-state writes and counts
// manifest installation. Embedding keeps every unrelated Store operation on
// the real in-memory implementation.
type durabilityStore struct {
	mailkey.Store
	identityErr     error
	capabilityErr   error
	identityCalls   int
	capabilityCalls int
	installCalls    int
}

func (s *durabilityStore) SetIdentity(ctx context.Context, domain string, st mailkey.IdentityState) error {
	s.identityCalls++
	if s.identityErr != nil {
		return s.identityErr
	}
	return s.Store.SetIdentity(ctx, domain, st)
}

func (s *durabilityStore) MarkValidated(ctx context.Context, domain string, at time.Time) error {
	s.capabilityCalls++
	if s.capabilityErr != nil {
		return s.capabilityErr
	}
	return s.Store.MarkValidated(ctx, domain, at)
}

func (s *durabilityStore) InstallManifest(ctx context.Context, domain string, res mailkey.Result) error {
	s.installCalls++
	return s.Store.InstallManifest(ctx, domain, res)
}

/*
TestTrustStatePersistenceIsAnAcceptancePrecondition covers the storage failure
that would otherwise become a downgrade:

  - the authority answered successfully;
  - persisting either the capability latch or the identity state failed;
  - no manifest may be installed or returned; and
  - the error must carry ErrEncryptionRequired, because upstream treats an
    ordinary resolution error as opportunistic "no key" and may send plaintext.

The call counts also pin the write order. A latch failure must prevent the
identity write; an identity failure happens only after the latch is durable, so
the only possible partial state fails closed.
*/
func TestTrustStatePersistenceIsAnAcceptancePrecondition(t *testing.T) {
	const domain = "example.com"
	now := time.Unix(1_750_000_000, 0).UTC()
	storeErr := errors.New("durable store unavailable")

	for _, tc := range []struct {
		name          string
		identityErr   error
		capabilityErr error
		wantIdentity  int
		wantLatch     bool
	}{
		{
			name:          "capability latch fails",
			capabilityErr: storeErr,
			wantIdentity:  0,
			wantLatch:     false,
		},
		{
			name:         "identity state fails",
			identityErr:  storeErr,
			wantIdentity: 1,
			wantLatch:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := peer.NewMemStore(func() time.Time { return now })
			store := &durabilityStore{
				Store: base, identityErr: tc.identityErr, capabilityErr: tc.capabilityErr,
			}
			svc := peer.NewService(&fixedResolver{res: realResult(t, domain, now, 1)}, store,
				peer.Options{Now: func() time.Time { return now }})
			t.Cleanup(svc.Close)

			res, err := svc.ResolveForEncryption(context.Background(), domain)
			if !errors.Is(err, mailkey.ErrEncryptionRequired) {
				t.Fatalf("durability failure returned %v; upstream could downgrade it to plaintext", err)
			}
			if res.Manifest.Domain != "" {
				t.Fatalf("durability failure returned the fetched manifest: %+v", res)
			}
			if store.installCalls != 0 {
				t.Fatalf("manifest installed %d times before trust state was durable", store.installCalls)
			}
			if store.capabilityCalls != 1 || store.identityCalls != tc.wantIdentity {
				t.Fatalf("write order: latch calls=%d identity calls=%d, want 1/%d",
					store.capabilityCalls, store.identityCalls, tc.wantIdentity)
			}
			p, perr := base.GetPeer(context.Background(), domain)
			if perr != nil {
				t.Fatal(perr)
			}
			if p != nil && p.Effective != nil {
				t.Fatal("a manifest became effective despite failed trust-state persistence")
			}
			capability, cerr := base.Capability(context.Background(), domain)
			if cerr != nil {
				t.Fatal(cerr)
			}
			if capability.Requires() != tc.wantLatch {
				t.Fatalf("capability latch requires=%v, want %v: %+v",
					capability.Requires(), tc.wantLatch, capability)
			}
		})
	}
}
