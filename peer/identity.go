/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/mailnite/mailkey"
)

/*
The sender side of the identity extension: what a sender does with a manifest,
given what it already trusts about the domain.

This is one pure function over (peer state, fetch result) because the decision is
the security property. Spread across a resolver, a store and a queue it would be
five decisions that mostly agree; here it is one table that can be read against
the spec and tested exhaustively.

Two ideas do the work, and confusing them is the mistake this file exists to
prevent:

  - A PROOF is evidence about bytes. "Internally consistent" means the signature
    verifies under a key whose fingerprint matches the one presented — which an
    attacker's own proof satisfies perfectly.
  - A PIN is a decision about a party, kept over time. Only a pin makes a proof
    mean anything.

So a valid proof from an unknown signer is not authentication; it is a candidate
for pinning, and whether to pin it depends on corroboration.
*/

// Verdict is what a sender should do with a fetched manifest.
type Verdict struct {
	// Encrypt reports whether mail may still be sealed: either with this fetched
	// manifest, when AcceptFetched is true, or with the previously accepted cache.
	// False means HOLD — never plaintext. Keeping this separate from
	// AcceptFetched is essential: a refused response must not become installable
	// merely because the trusted cached manifest remains usable.
	Encrypt bool
	// AcceptFetched reports whether the manifest in the fetch result passed the
	// identity decision and may be installed. False with Encrypt=true means
	// REFUSE THIS RESPONSE and use the trusted cached manifest instead.
	AcceptFetched bool
	// Pin is the identity to establish or keep. Empty when nothing is pinned.
	Pin      mailkey.Fingerprint
	HasPin   bool
	Status   mailkey.IdentityStatus
	Alert    string
	Contest  string
	Rollback bool
	// Reason is the matrix row that produced this verdict, for logs and tests.
	Reason string
}

/*
DecideIdentity applies §6.2, plus the replay rules of §6.4.

`dnsFP`/`hasDNSFP` are the DNS observation for this fetch; DNS is corroboration
only, and every branch below keeps that true — it can cause a pin to be withheld,
never to be created, replaced or bypassed.

`cachedUsable` reports whether the sender still holds a valid manifest signed by
the pin. It decides the difference between refusing this response and having
nothing at all to send with.
*/
func DecideIdentity(p *mailkey.Peer, res mailkey.Result, dnsFP mailkey.Fingerprint, hasDNSFP bool, cachedUsable bool) Verdict {
	cur := mailkey.IdentityState{}
	if p != nil {
		cur = p.Identity
	}
	// A record written before this extension existed carries the zero status.
	// Normalized once, here, rather than leaving every consumer to know that ""
	// means unpinned — a comparison against IdentityUnpinned that silently fails
	// for stored peers is exactly the kind of gap that reads as correct.
	if cur.Status == "" {
		cur.Status = mailkey.IdentityUnpinned
	}
	proofValid := res.Proof != nil && res.ProofError == ""
	proofBroken := res.ProofError != ""

	pinned := cur.Status == mailkey.IdentityPinned
	switch {
	// --- pinned rows --------------------------------------------------------
	case pinned && proofValid && res.Proof.Fingerprint == cur.Fingerprint:
		out := Verdict{
			Encrypt: true, AcceptFetched: true, Pin: cur.Fingerprint, HasPin: true,
			Status: mailkey.IdentityPinned, Reason: "pinned/valid-proof-from-pin",
		}
		if hasDNSFP && dnsFP != cur.Fingerprint {
			// DNS disagrees with an established pin. Keep the pin — an
			// unauthenticated record must not move a trust anchor — and say so.
			out.Alert = "DNS advertises a different identity fingerprint than the pinned one; the pin stands and delivery is unaffected"
			out.Reason = "pinned/dns-disagrees"
		}
		return afterIdentityAuthorization(cur, res, cachedUsable, out)

	case pinned && proofValid:
		// Correctly signed, by someone else. This is either an identity
		// rotation we have not been shown proof of, or a takeover. They are
		// indistinguishable without the rotation chain (§5), so the answer is
		// the same: refuse, and fall back to what the pin already authorized.
		return Verdict{
			Encrypt: cachedUsable, Pin: cur.Fingerprint, HasPin: true,
			Status: mailkey.IdentityPinned,
			Alert: fmt.Sprintf("the authority for this domain is now signing with identity %s, which is not the pinned one — refusing it until an authorized rotation is presented",
				short(res.Proof.Fingerprint)),
			Reason: "pinned/valid-proof-other-signer",
		}

	case pinned:
		// Absent or invalid where a pin exists. Stripping the proof is
		// indistinguishable from an attack once a pin is established, which is
		// exactly the asymmetry §6.3 describes: adoption starts weak, but a
		// pinned relationship is fail-closed.
		what := "carried no identity proof"
		if proofBroken {
			what = "carried an invalid identity proof (" + res.ProofError + ")"
		}
		return Verdict{
			Encrypt: cachedUsable, Pin: cur.Fingerprint, HasPin: true,
			Status: mailkey.IdentityPinned,
			Alert:  "the authority for this pinned domain " + what + "; refusing this response",
			Reason: "pinned/proof-absent-or-invalid",
		}

	// --- unpinned rows ------------------------------------------------------
	case proofBroken:
		// Present and wrong on an unpinned domain: encrypt as before, do not
		// pin, and alert. Pinning here would let a broken or hostile authority
		// choose the anchor.
		return afterIdentityAuthorization(cur, res, cachedUsable, Verdict{
			Encrypt: true, AcceptFetched: true, Status: cur.Status,
			Alert:  "this domain served a malformed identity proof (" + res.ProofError + "); encrypting without establishing a pin",
			Reason: "unpinned/invalid-proof",
		})

	case !proofValid && hasDNSFP:
		// DNS says the domain has an identity; the response carried none. Either
		// an intermediary stripped it or the deployment is inconsistent. Both
		// are worth saying; neither changes what we send.
		return afterIdentityAuthorization(cur, res, cachedUsable, Verdict{
			Encrypt: true, AcceptFetched: true, Status: cur.Status,
			Alert:  "DNS advertises an identity fingerprint for this domain but the authority served no proof — the proof may have been stripped in transit, or the deployment is inconsistent",
			Reason: "unpinned/dns-fp-but-no-proof",
		})

	case !proofValid:
		// An unsigned domain. Legacy MKDP1, and the majority case during
		// adoption. Nothing to pin, nothing to alert about.
		return afterIdentityAuthorization(cur, res, cachedUsable,
			Verdict{Encrypt: true, AcceptFetched: true, Status: cur.Status, Reason: "unpinned/no-proof"})

	case hasDNSFP && dnsFP != res.Proof.Fingerprint:
		// A valid proof the DNS channel disagrees with. Encrypt — the manifest
		// IS WebPKI-authenticated — but withhold the pin, because an attacker
		// holding only the TLS path would otherwise make a false anchor
		// permanent. Requiring them to also control the observed DNS channel is
		// the entire value of unauthenticated corroboration.
		return afterIdentityAuthorization(cur, res, cachedUsable, Verdict{
			Encrypt: true, AcceptFetched: true, Status: mailkey.IdentityContested,
			Contest: fmt.Sprintf("HTTPS signs with %s, DNS advertises %s", short(res.Proof.Fingerprint), short(dnsFP)),
			Alert: "Message encrypted using a WebPKI-authenticated but unpinned identity. " +
				"DNS advertised a different identity. Persistent pinning was withheld.",
			Reason: "unpinned/dns-disagrees",
		})

	default:
		// A valid proof, and either DNS corroborates it or DNS says nothing.
		// This is where a pin is born.
		out := Verdict{
			Encrypt: true, AcceptFetched: true, Pin: res.Proof.Fingerprint, HasPin: true,
			Status: mailkey.IdentityPinned, Reason: "unpinned/pin-established",
		}
		if hasDNSFP {
			out.Reason = "unpinned/pin-established-dns-corroborated"
		}
		return afterIdentityAuthorization(cur, res, cachedUsable, out)
	}
}

// afterIdentityAuthorization applies replay ordering only after the identity
// matrix has authorized the fetched response. Ordering cannot authenticate a
// signer: checking it first would let a different or missing signer bypass an
// established pin merely by copying an accepted issued_at value.
func afterIdentityAuthorization(cur mailkey.IdentityState, res mailkey.Result, cachedUsable bool, accepted Verdict) Verdict {
	if !accepted.AcceptFetched {
		return accepted
	}
	if replay, found := checkReplay(cur, res, cachedUsable); found {
		return replay
	}
	return accepted
}

/*
checkReplay implements §6.4.

An expired manifest is refused outright — it can never authorize new encryption,
whoever signed it. Then two orderings, both measured against what this sender has
ALREADY verified rather than against anything in the response:

  - an older issued_at is a rollback and must not replace the newer effective
    manifest;
  - the same issued_at under a different manifest_id means the authority produced
    two different authorizations for one instant, which MKDP1 reports and refuses
    rather than tie-breaking by arrival order.

Note what is deliberately absent: any unsigned ordering value carried on the
wire. That is the `seq` defect MKDP1 was created to remove, and adding it back as
a header would reintroduce it exactly.
*/
func checkReplay(cur mailkey.IdentityState, res mailkey.Result, cachedUsable bool) (Verdict, bool) {
	if !res.ExpiresAt.IsZero() && !res.ExpiresAt.After(res.FetchedAt) {
		return Verdict{
			Encrypt: cachedUsable, Status: cur.Status,
			Alert:  "the authority served an already-expired manifest; it cannot authorize new encryption",
			Reason: "replay/expired",
		}, true
	}
	if cur.LastVerifiedIssuedAt.IsZero() {
		return Verdict{}, false
	}
	issued := res.Manifest.IssuedAt
	switch {
	case issued.Before(cur.LastVerifiedIssuedAt):
		return Verdict{
			Encrypt: cachedUsable, Pin: cur.Fingerprint, HasPin: cur.Status == mailkey.IdentityPinned,
			Status:   cur.Status,
			Rollback: true,
			Alert: fmt.Sprintf("the authority served a manifest issued %s, older than the %s already verified — a replay of an earlier authorization",
				issued.UTC().Format(time.RFC3339), cur.LastVerifiedIssuedAt.UTC().Format(time.RFC3339)),
			Reason: "replay/rollback",
		}, true
	case issued.Equal(cur.LastVerifiedIssuedAt) && res.ManifestID != cur.LastVerifiedManifestID:
		// There is no authenticated ordering between two different manifests
		// stamped at the same instant. Report the instability and keep using the
		// previously accepted cache; when none remains usable, hold rather than
		// letting an ambiguous response replace known state.
		return Verdict{
			Encrypt: cachedUsable, Pin: cur.Fingerprint, HasPin: cur.Status == mailkey.IdentityPinned,
			Status: cur.Status,
			Alert:  "the authority served two different manifests carrying the same issue time — refusing the ambiguous response and keeping the previously accepted manifest",
			Reason: "replay/same-issued-different-id",
		}, true
	}
	return Verdict{}, false
}

/*
ApplyIdentity folds a verdict into the peer's persisted identity state.

EverHTTPSValidated is set here and NOWHERE conditionally: any successful HTTPS
retrieval sets it, including an unsigned one, including one whose pin was
withheld, and including one this verdict refuses. It is a statement about the
transport, not about trust, and it is what stops a later discovery outage from
being read as "this domain does not do MKDP1" (04-SECURITY §7).
*/
func ApplyIdentity(st mailkey.IdentityState, v Verdict, res mailkey.Result, now time.Time) mailkey.IdentityState {
	st.EverHTTPSValidated = true
	if st.Status == "" {
		st.Status = mailkey.IdentityUnpinned
	}

	switch {
	case v.HasPin && st.Status != mailkey.IdentityPinned:
		st.Status = mailkey.IdentityPinned
		st.Fingerprint = v.Pin
		st.PinnedAt = now
		st.Contested = ""
		// The KEY travels with the pin, because the fingerprint alone cannot
		// verify the first link of a rotation chain. Only when the proof is the
		// identity being pinned — a mismatched pair must store nothing.
		if res.Proof != nil && res.Proof.Fingerprint == v.Pin {
			st.PinnedPublicKey = append([]byte(nil), res.Proof.PublicKey...)
		}
	case v.Status == mailkey.IdentityContested:
		// Withheld, not weakened: an existing pin is never demoted by DNS.
		if st.Status != mailkey.IdentityPinned {
			st.Status = mailkey.IdentityContested
			st.Contested = v.Contest
		}
	}

	// The replay watermark advances only on a manifest this sender ACCEPTED.
	// Advancing it on a refused response would let one rejected replay raise the
	// bar against the genuine newer manifest that follows.
	if v.AcceptFetched && !res.Manifest.IssuedAt.IsZero() && res.Manifest.IssuedAt.After(st.LastVerifiedIssuedAt) {
		st.LastVerifiedIssuedAt = res.Manifest.IssuedAt
		st.LastVerifiedManifestID = res.ManifestID
	}
	return st
}

// ObserveDNSFingerprint records a DNS-advertised fingerprint. It is stored as an
// observation and never installs, replaces or removes a pin.
func ObserveDNSFingerprint(st mailkey.IdentityState, fp mailkey.Fingerprint, has bool) mailkey.IdentityState {
	st.DNSFingerprint, st.HasDNSFP = fp, has
	return st
}

func short(fp mailkey.Fingerprint) string {
	// Twelve characters for a HUMAN-readable log line only. Never compare
	// fingerprints in this form — the full digest is the trust anchor.
	s := encodeFP(fp)
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// encodeFP renders a fingerprint as unpadded base64url. Local so peer/ keeps its
// dependency surface (manifest owns the identical codec for ids, but importing
// it here for one line would couple the trust state to the manifest parser).
func encodeFP(fp mailkey.Fingerprint) string {
	return base64.RawURLEncoding.EncodeToString(fp[:])
}
