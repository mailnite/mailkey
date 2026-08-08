/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/peer"
)

/*
The §6.2 matrix, every row.

It is worth stating why this is a table test rather than a set of scenarios: the
rows are not variations on a theme, they are NINE DIFFERENT ANSWERS to nearly
identical inputs, and the differences are the security property. "Valid proof,
unpinned, DNS agrees" pins. "Valid proof, unpinned, DNS disagrees" deliberately
does not — same proof, same validity, opposite outcome — because a pin an
attacker on the TLS path can create is worse than no pin at all.

Two invariants hold across every row and are asserted for all of them:

  - a domain that has ever answered over HTTPS never falls back to plaintext.
    Refusing an identity means HOLD, never send in the clear;
  - DNS never installs, replaces or bypasses a pin. It can only withhold one, or
    raise an alert.
*/

func fpFor(t *testing.T, domain string, seed byte) (mailkey.Fingerprint, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	pk := priv.Public().(ed25519.PublicKey)
	fp, err := identity.FingerprintOf(domain, pk)
	if err != nil {
		t.Fatal(err)
	}
	return fp, pk, priv
}

// result builds a fetch result for the domain, optionally signed by seed.
func result(t *testing.T, domain string, issued time.Time, signSeed int) mailkey.Result {
	t.Helper()
	raw := []byte("canonical manifest bytes for " + domain)
	res := mailkey.Result{
		Manifest:   mailkey.Manifest{Domain: domain, IssuedAt: issued, ExpiresAt: issued.Add(7 * 24 * time.Hour)},
		ManifestID: mailkey.ManifestID{1, 2, 3},
		Raw:        raw,
		FetchedAt:  issued,
		ExpiresAt:  issued.Add(7 * 24 * time.Hour),
	}
	if signSeed > 0 {
		fp, pk, priv := fpFor(t, domain, byte(signSeed))
		sig, err := identity.SignManifest(priv, domain, raw)
		if err != nil {
			t.Fatal(err)
		}
		res.Proof = &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}
	}
	return res
}

func pinnedPeer(t *testing.T, domain string, seed int) *mailkey.Peer {
	t.Helper()
	fp, _, _ := fpFor(t, domain, byte(seed))
	return &mailkey.Peer{Domain: domain, Identity: mailkey.IdentityState{
		Status: mailkey.IdentityPinned, Fingerprint: fp, EverHTTPSValidated: true,
	}}
}

func TestIdentityMatrix(t *testing.T) {
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	ourFP, _, _ := fpFor(t, dom, 1)
	otherFP, _, _ := fpFor(t, dom, 9)

	broken := result(t, dom, now, 0)
	broken.ProofError = "proof: incomplete — all three fields are required together"

	cases := []struct {
		name        string
		peer        *mailkey.Peer
		res         mailkey.Result
		dnsFP       mailkey.Fingerprint
		hasDNS      bool
		cached      bool
		wantEncrypt bool
		wantFetched bool
		wantStatus  mailkey.IdentityStatus
		wantPin     bool
		wantAlert   bool
		wantReason  string
	}{
		{
			name: "unpinned, no proof — legacy WebPKI, do not pin",
			res:  result(t, dom, now, 0), wantEncrypt: true, wantFetched: true,
			wantStatus: mailkey.IdentityUnpinned, wantReason: "unpinned/no-proof",
		},
		{
			name: "unpinned, invalid proof — encrypt, do not pin, alert",
			res:  broken, wantEncrypt: true, wantFetched: true, wantAlert: true,
			wantStatus: mailkey.IdentityUnpinned, wantReason: "unpinned/invalid-proof",
		},
		{
			name: "unpinned, DNS fp present, proof absent — alert possible stripping",
			res:  result(t, dom, now, 0), dnsFP: ourFP, hasDNS: true,
			wantEncrypt: true, wantFetched: true, wantAlert: true,
			wantStatus: mailkey.IdentityUnpinned, wantReason: "unpinned/dns-fp-but-no-proof",
		},
		{
			name: "unpinned, DNS matches a valid proof — pin it",
			res:  result(t, dom, now, 1), dnsFP: ourFP, hasDNS: true,
			wantEncrypt: true, wantFetched: true, wantPin: true,
			wantStatus: mailkey.IdentityPinned, wantReason: "unpinned/pin-established-dns-corroborated",
		},
		{
			name:        "unpinned, no DNS opinion, valid proof — pin it",
			res:         result(t, dom, now, 1),
			wantEncrypt: true, wantFetched: true, wantPin: true,
			wantStatus: mailkey.IdentityPinned, wantReason: "unpinned/pin-established",
		},
		{
			name: "unpinned, DNS disagrees with a valid proof — encrypt, WITHHOLD the pin",
			res:  result(t, dom, now, 1), dnsFP: otherFP, hasDNS: true,
			wantEncrypt: true, wantFetched: true, wantAlert: true,
			wantStatus: mailkey.IdentityContested, wantReason: "unpinned/dns-disagrees",
		},
		{
			name: "pinned, valid proof from the pin — accept",
			peer: pinnedPeer(t, dom, 1), res: result(t, dom, now, 1),
			wantEncrypt: true, wantFetched: true, wantPin: true,
			wantStatus: mailkey.IdentityPinned, wantReason: "pinned/valid-proof-from-pin",
		},
		{
			name: "pinned, proof absent, cached manifest available — refuse, use the cache",
			peer: pinnedPeer(t, dom, 1), res: result(t, dom, now, 0), cached: true,
			wantEncrypt: true, wantAlert: true, wantPin: true,
			wantStatus: mailkey.IdentityPinned, wantReason: "pinned/proof-absent-or-invalid",
		},
		{
			name: "pinned, proof absent, nothing cached — HOLD",
			peer: pinnedPeer(t, dom, 1), res: result(t, dom, now, 0),
			wantEncrypt: false, wantAlert: true, wantPin: true,
			wantStatus: mailkey.IdentityPinned, wantReason: "pinned/proof-absent-or-invalid",
		},
		{
			name: "pinned, valid proof from ANOTHER signer — refuse until a rotation is shown",
			peer: pinnedPeer(t, dom, 1), res: result(t, dom, now, 9),
			wantEncrypt: false, wantAlert: true, wantPin: true,
			wantStatus: mailkey.IdentityPinned, wantReason: "pinned/valid-proof-other-signer",
		},
		{
			name: "pinned, DNS disagrees — keep the pin, alert, delivery unaffected",
			peer: pinnedPeer(t, dom, 1), res: result(t, dom, now, 1),
			dnsFP: otherFP, hasDNS: true,
			wantEncrypt: true, wantFetched: true, wantAlert: true, wantPin: true,
			wantStatus: mailkey.IdentityPinned, wantReason: "pinned/dns-disagrees",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := peer.DecideIdentity(tc.peer, tc.res, tc.dnsFP, tc.hasDNS, tc.cached)
			if v.Reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", v.Reason, tc.wantReason)
			}
			if v.Encrypt != tc.wantEncrypt {
				t.Fatalf("encrypt = %v, want %v", v.Encrypt, tc.wantEncrypt)
			}
			if v.AcceptFetched != tc.wantFetched {
				t.Fatalf("acceptFetched = %v, want %v", v.AcceptFetched, tc.wantFetched)
			}
			if v.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", v.Status, tc.wantStatus)
			}
			if v.HasPin != tc.wantPin {
				t.Fatalf("hasPin = %v, want %v", v.HasPin, tc.wantPin)
			}
			if (v.Alert != "") != tc.wantAlert {
				t.Fatalf("alert = %q, want any=%v", v.Alert, tc.wantAlert)
			}

			// Invariant: DNS never installs or moves a pin. Whatever this row
			// decided, re-running it with the DNS observation REMOVED must not
			// produce a different pin — only a different alert or status.
			noDNS := peer.DecideIdentity(tc.peer, tc.res, mailkey.Fingerprint{}, false, tc.cached)
			if v.HasPin && noDNS.HasPin && v.Pin != noDNS.Pin {
				t.Fatalf("the DNS observation changed WHICH identity was pinned: %x vs %x", v.Pin, noDNS.Pin)
			}
		})
	}
}

/*
TestRefusalNeverMeansPlaintext is 04-SECURITY §7 restated at this layer.

Every refusal in the matrix is "hold this message", never "send it in the clear".
The distinction is the entire value of the extension: an attacker who can strip a
proof or serve a stale manifest can, at worst, delay mail. If any refusal
degraded to plaintext, stripping a header would become a downgrade to cleartext —
strictly worse than having no identity layer at all.
*/
func TestRefusalNeverMeansPlaintext(t *testing.T) {
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	p := pinnedPeer(t, dom, 1)

	for _, res := range []mailkey.Result{
		result(t, dom, now, 0), // proof stripped
		result(t, dom, now, 9), // signed by someone else
	} {
		v := peer.DecideIdentity(p, res, mailkey.Fingerprint{}, false, false)
		if v.Encrypt {
			t.Fatalf("%s: refusal must not permit this manifest", v.Reason)
		}
		// The pin survives the refusal. A refused response must never be able to
		// clear the anchor it failed against — that would make one stripped
		// header enough to unpin a domain.
		st := peer.ApplyIdentity(p.Identity, v, res, now)
		if st.Status != mailkey.IdentityPinned || st.Fingerprint != p.Identity.Fingerprint {
			t.Fatalf("a refused response changed the pin: %+v", st)
		}
		// And downgrade protection stays on.
		if !st.EverHTTPSValidated {
			t.Fatal("EverHTTPSValidated was cleared")
		}
	}
}

/*
TestReplayProtection is §6.4.

A signature says WHO authorized these bytes. It says nothing about WHEN, so an
attacker able to serve responses could return yesterday's perfectly-signed
manifest forever — pinning the domain to a key whose private half they may since
have obtained, or simply freezing it against a rotation.

The defense is a watermark of what this sender has already verified. Note the
asymmetry in ApplyIdentity: the watermark advances only on an ACCEPTED manifest.
Advancing it on a refused one would let a single rejected replay raise the bar
against the genuine newer manifest that follows.
*/
func TestReplayProtection(t *testing.T) {
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	p := pinnedPeer(t, dom, 1)

	fresh := result(t, dom, now, 1)
	v := peer.DecideIdentity(p, fresh, mailkey.Fingerprint{}, false, true)
	if !v.Encrypt {
		t.Fatalf("the current manifest must be accepted: %s", v.Reason)
	}
	p.Identity = peer.ApplyIdentity(p.Identity, v, fresh, now)
	if !p.Identity.LastVerifiedIssuedAt.Equal(now) || p.Identity.LastVerifiedManifestID != fresh.ManifestID {
		t.Fatalf("the watermark did not advance: %+v", p.Identity)
	}

	// An OLDER issued_at, correctly signed by the pin: a rollback.
	old := result(t, dom, now.Add(-48*time.Hour), 1)
	old.FetchedAt = now
	old.ExpiresAt = now.Add(24 * time.Hour)
	v = peer.DecideIdentity(p, old, mailkey.Fingerprint{}, false, true)
	if v.Encrypt || !v.Rollback || v.Reason != "replay/rollback" {
		t.Fatalf("a replayed older manifest was accepted: %+v", v)
	}
	// The refusal must not move the watermark backwards.
	after := peer.ApplyIdentity(p.Identity, v, old, now)
	if !after.LastVerifiedIssuedAt.Equal(now) {
		t.Fatalf("a rejected replay moved the watermark to %s", after.LastVerifiedIssuedAt)
	}

	// The SAME issued_at under a different manifest id: two authorizations for
	// one instant. MKDP1 reports rather than tie-breaks.
	twin := result(t, dom, now, 1)
	twin.ManifestID = mailkey.ManifestID{9, 9, 9}
	// Reported, not refused: §6.4 calls this an alert. Refusing would make an
	// authority whose clock granularity produced two manifests in one second
	// undeliverable, and MKDP1's answer to ambiguity is to surface it for a
	// human rather than to invent a tie-break or to punish.
	v = peer.DecideIdentity(p, twin, mailkey.Fingerprint{}, false, true)
	if v.Reason != "replay/same-issued-different-id" || v.Alert == "" {
		t.Fatalf("an unstable authority was not reported: %+v", v)
	}
	if !v.Encrypt {
		t.Fatal("instability is an alert, not a refusal — this would strand mail on a publisher bug")
	}

	// An already-expired manifest can never authorize new encryption, whoever
	// signed it and whatever the watermark says.
	expired := result(t, dom, now, 1)
	expired.ExpiresAt = now.Add(-time.Second)
	v = peer.DecideIdentity(nil, expired, mailkey.Fingerprint{}, false, false)
	if v.Encrypt || v.Reason != "replay/expired" {
		t.Fatalf("an expired manifest was accepted: %+v", v)
	}

	// A NEWER manifest still gets through — the defense must not freeze the
	// domain at the first thing it saw.
	newer := result(t, dom, now.Add(time.Hour), 1)
	v = peer.DecideIdentity(p, newer, mailkey.Fingerprint{}, false, true)
	if !v.Encrypt {
		t.Fatalf("a newer manifest was refused: %+v", v)
	}
}

/*
TestEverHTTPSValidatedSurvivesEverything: one successful HTTPS retrieval turns on
downgrade protection permanently, whatever else happened.

Including an unsigned manifest, including a contested one, and including a
response this sender refused. It is a statement about the transport, not about
trust — and it is what stops a later discovery outage from being read as "this
domain does not speak MKDP1" and mail going out in the clear.
*/
func TestEverHTTPSValidatedSurvivesEverything(t *testing.T) {
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	otherFP, _, _ := fpFor(t, dom, 9)

	for name, tc := range map[string]struct {
		p   *mailkey.Peer
		res mailkey.Result
		dns bool
	}{
		"unsigned":  {res: result(t, dom, now, 0)},
		"contested": {res: result(t, dom, now, 1), dns: true},
		"refused":   {p: pinnedPeer(t, dom, 1), res: result(t, dom, now, 9)},
	} {
		t.Run(name, func(t *testing.T) {
			var st mailkey.IdentityState
			if tc.p != nil {
				st = tc.p.Identity
			}
			v := peer.DecideIdentity(tc.p, tc.res, otherFP, tc.dns, false)
			got := peer.ApplyIdentity(st, v, tc.res, now)
			if !got.EverHTTPSValidated {
				t.Fatal("a successful HTTPS fetch must set EverHTTPSValidated")
			}
		})
	}
}

// TestContestedNeverDemotesAPin: DNS disagreement withholds a pin that does not
// exist yet; it must not weaken one that does. Otherwise anyone able to influence
// the observed DNS channel could downgrade an established relationship.
func TestContestedNeverDemotesAPin(t *testing.T) {
	const dom = "example.com"
	now := time.Unix(1750000000, 0).UTC()
	p := pinnedPeer(t, dom, 1)
	otherFP, _, _ := fpFor(t, dom, 9)

	res := result(t, dom, now, 1)
	v := peer.DecideIdentity(p, res, otherFP, true, true)
	st := peer.ApplyIdentity(p.Identity, v, res, now)
	if st.Status != mailkey.IdentityPinned || st.Fingerprint != p.Identity.Fingerprint {
		t.Fatalf("DNS disagreement demoted an established pin: %+v", st)
	}
	if v.Alert == "" {
		t.Fatal("the disagreement must still be reported")
	}
}

// TestDNSObservationIsOnlyAnObservation: recording a fingerprint from DNS stores
// it and changes nothing else. It is the one place a DNS value is written to
// peer state, so it is worth pinning that it writes only the observation fields.
func TestDNSObservationIsOnlyAnObservation(t *testing.T) {
	const dom = "example.com"
	before := pinnedPeer(t, dom, 1).Identity
	otherFP, _, _ := fpFor(t, dom, 9)

	after := peer.ObserveDNSFingerprint(before, otherFP, true)
	if after.Status != before.Status || after.Fingerprint != before.Fingerprint {
		t.Fatalf("a DNS observation changed the pin: %+v → %+v", before, after)
	}
	if !after.HasDNSFP || after.DNSFingerprint != otherFP {
		t.Fatal("the observation was not recorded")
	}
}
