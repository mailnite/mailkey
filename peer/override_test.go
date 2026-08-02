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

type fixedResolver struct{ res mailkey.Result }

func (f *fixedResolver) Resolve(context.Context, string) (mailkey.Result, error) {
	return f.res, nil
}

// overrideEnv is a domain PINNED to one identity whose authority now answers,
// validly, signed by another. That is the shape of both a legitimate rotation
// and an authority takeover, which is exactly why MKDP1 refuses to guess and
// asks a human instead.
func overrideEnv(t *testing.T, dom string, now time.Time) (*peer.Service, *peer.MemStore, mailkey.Fingerprint) {
	t.Helper()
	store := peer.NewMemStore(func() time.Time { return now })
	ourFP, _, _ := fpFor(t, dom, 1)
	if err := store.SetIdentity(context.Background(), dom, mailkey.IdentityState{
		Status: mailkey.IdentityPinned, Fingerprint: ourFP, EverHTTPSValidated: true,
	}); err != nil {
		t.Fatal(err)
	}
	svc := peer.NewService(&fixedResolver{res: result(t, dom, now, 9)}, store, peer.Options{
		Now: func() time.Time { return now },
	})
	t.Cleanup(svc.Close)
	return svc, store, ourFP
}

/*
TestOverrideProceedsWithoutMovingThePin is the whole point of the ask.

A sender who says "send anyway" is answering a question about ONE message. If
the answer also re-pinned the domain, the fastest way to defeat identity pinning
would be to take over an authority and wait for somebody in a hurry — and the
person who did it would never know they had made an administrative decision.

So: the manifest comes back usable, and everything durable is exactly as it was.
*/
func TestOverrideProceedsWithoutMovingThePin(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	svc, store, ourFP := overrideEnv(t, dom, now)

	if _, err := svc.ResolveForEncryption(ctx, dom); err == nil {
		t.Fatal("a manifest signed by an unpinned identity was accepted without anyone being asked")
	}
	res, err := svc.ResolveAcceptingUnpinned(ctx, dom)
	if err != nil {
		t.Fatalf("the sender said yes and the message was still held: %v", err)
	}
	if res.Proof == nil {
		t.Fatal("proceeding returned a manifest with no proof — that is cleartext wearing an override")
	}

	p, err := store.GetPeer(ctx, dom)
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity.Fingerprint != ourFP {
		t.Fatalf("the override moved the pin to %x — a sender in a hurry became an administrator", p.Identity.Fingerprint)
	}
	if p.Effective != nil {
		t.Fatal("the override INSTALLED the manifest; the next message would be sealed to it without asking anyone")
	}
	// And the question is asked again, because nothing was decided durably.
	if _, err := svc.ResolveForEncryption(ctx, dom); err == nil {
		t.Fatal("the second message went out unasked — the override outlived its message")
	}
}

/*
TestOverrideNeverProceedsPastAReplay.

A replayed manifest is a real, validly signed one — that is what makes it
dangerous. It names a key we have already superseded, quite possibly because it
was compromised, and an attacker serving it needs the sender to click "send
anyway" exactly once.

A pin disagreement is a question a human can reasonably answer. A rollback is
not, and the surfaces must never be offered the chance to ask.
*/
func TestOverrideNeverProceedsPastAReplay(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	store := peer.NewMemStore(func() time.Time { return now })
	fp, _, _ := fpFor(t, dom, 1)
	if err := store.SetIdentity(ctx, dom, mailkey.IdentityState{
		Status: mailkey.IdentityPinned, Fingerprint: fp, EverHTTPSValidated: true,
		LastVerifiedIssuedAt: now.Add(48 * time.Hour), // we have seen something NEWER
	}); err != nil {
		t.Fatal(err)
	}
	// Correctly signed by the pinned identity, and older than what we hold.
	svc := peer.NewService(&fixedResolver{res: result(t, dom, now, 1)}, store, peer.Options{
		Now: func() time.Time { return now },
	})
	t.Cleanup(svc.Close)

	if _, err := svc.ResolveForEncryption(ctx, dom); err == nil {
		t.Fatal("a rolled-back manifest was accepted")
	}
	_, err := svc.ResolveAcceptingUnpinned(ctx, dom)
	if err == nil {
		t.Fatal("a sender was able to send anyway past a ROLLBACK; one click would undo a key rotation")
	}
	// And it must not even be OFFERED: the narrow sentinel is what the surfaces
	// key their "send anyway" button off, so a replay must not carry it.
	if errors.Is(err, mailkey.ErrIdentityRefused) {
		t.Fatal("a replay refusal carries the identity sentinel — every surface would offer to override it")
	}
	if !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("a replay refusal must still hold the mail: %v", err)
	}
}

// TestOverrideCannotProduceCleartext: where there is no key there is nothing to
// return, so "proceed" cannot degrade into plaintext. The capability latch is
// not a check this path has to remember — it is a shape it cannot express.
func TestOverrideCannotProduceCleartext(t *testing.T) {
	ctx := context.Background()
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	store := peer.NewMemStore(func() time.Time { return now })
	if err := store.MarkValidated(ctx, dom, now); err != nil {
		t.Fatal(err)
	}
	svc := peer.NewService(
		&fakeResolver{err: mailkey.Failf(mailkey.FailureNetwork, dom, "authority unreachable")},
		store, peer.Options{Now: func() time.Time { return now }})
	t.Cleanup(svc.Close)

	res, err := svc.ResolveAcceptingUnpinned(ctx, dom)
	if err == nil {
		t.Fatalf("an override past the capability latch returned %+v — that is the silent downgrade, re-opened by consent", res)
	}
	if !errors.Is(err, mailkey.ErrEncryptionRequired) {
		t.Fatalf("the latch must still hold: %v", err)
	}
}
