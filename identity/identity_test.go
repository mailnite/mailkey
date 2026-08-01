/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/manifest"
)

// key returns a deterministic identity key so failures are reproducible.
func key(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

/*
TestFingerprintBindsDomainAndAlgorithm is the property that makes a pin worth
anything.

The fingerprint is what a sender remembers about a domain for years. If the raw
public key alone determined it, an operator of one domain could present the SAME
identity for another — pin example.com's trust anchor at a key they control
simply by publishing the same bytes — and a verifier comparing fingerprints would
agree. Putting the domain and the algorithm inside the preimage makes the
fingerprint mean "this key, for this domain, under this algorithm" and nothing
else.
*/
func TestFingerprintBindsDomainAndAlgorithm(t *testing.T) {
	pk, _ := key(t, 1)
	other, _ := key(t, 2)

	a, err := identity.FingerprintOf("example.com", pk)
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.FingerprintOf("example.net", pk)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("one public key produced the same fingerprint for two domains")
	}
	c, err := identity.FingerprintOf("example.com", other)
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("two public keys produced the same fingerprint")
	}
	// Deterministic, and normalization-stable: the pin must survive the domain
	// arriving in a different case or with a trailing dot.
	for _, spelling := range []string{"example.com", "EXAMPLE.COM", "Example.Com.", " example.com "} {
		got, err := identity.FingerprintOf(spelling, pk)
		if err != nil {
			t.Fatalf("%q: %v", spelling, err)
		}
		if got != a {
			t.Fatalf("%q produced a different fingerprint — a pin would not survive a re-spelled domain", spelling)
		}
	}
	// Never truncated, and one spelling on the wire.
	if s := manifest.EncodeID(a); len(s) != 43 {
		t.Fatalf("encoded fingerprint is %d chars, want 43 (a full 32-byte digest)", len(s))
	}
	// A key of the wrong size is refused rather than hashed into a plausible
	// looking value.
	if _, err := identity.FingerprintOf("example.com", ed25519.PublicKey("short")); err == nil {
		t.Fatal("a malformed public key must be refused")
	}
}

/*
TestSignatureIsBoundToDomainAndBytes covers the transcript.

Two lifting attacks are in scope. An authority hosting several domains can serve
byte-identical manifests for them; without the domain in the transcript, ONE
signature would be valid for all of them, and a proof could be moved between
authorities that happen to agree. And a signature over some other object must
never verify as a manifest proof, which is what the fixed context string is for.
*/
func TestSignatureIsBoundToDomainAndBytes(t *testing.T) {
	pk, priv := key(t, 3)
	raw := []byte("canonical manifest bytes, pretend these are msgpack")

	sig, err := identity.SignManifest(priv, "example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.VerifyManifest(pk, "example.com", raw, sig); err != nil {
		t.Fatalf("a signature must verify over its own inputs: %v", err)
	}
	// Lifted to another domain.
	if err := identity.VerifyManifest(pk, "example.net", raw, sig); err == nil {
		t.Fatal("a proof must not verify for a different domain")
	}
	// Applied to different bytes.
	if err := identity.VerifyManifest(pk, "example.com", append(raw, '!'), sig); err == nil {
		t.Fatal("a proof must not verify over different manifest bytes")
	}
	// Under another key.
	otherPk, _ := key(t, 4)
	if err := identity.VerifyManifest(otherPk, "example.com", raw, sig); err == nil {
		t.Fatal("a proof must not verify under a different identity key")
	}
	// A raw Ed25519 signature over the manifest bytes WITHOUT the context and
	// domain must not pass — that is the cross-protocol reuse the context
	// prevents, and it is the shape a naive implementation would produce.
	bare := ed25519.Sign(priv, raw)
	if err := identity.VerifyManifest(pk, "example.com", raw, bare); err == nil {
		t.Fatal("a context-less signature verified — domain separation is not in force")
	}
	// Malformed inputs are refused, not treated as failures to verify later.
	if _, err := identity.SignManifest(priv, "example.com", nil); err == nil {
		t.Fatal("signing empty manifest bytes must be refused")
	}
	if err := identity.VerifyManifest(pk, "example.com", raw, sig[:10]); err == nil {
		t.Fatal("a short signature must be refused")
	}
}

// TestCheckRequiresTheFingerprintToMatchTheKey: Mail-Key-Signer is a CLAIM. A
// server naming a fingerprint its own key does not produce must be rejected,
// because a verifier that trusted the claimed value could be pointed at a pin it
// already holds while signing with something else entirely.
func TestCheckRequiresTheFingerprintToMatchTheKey(t *testing.T) {
	pk, priv := key(t, 5)
	raw := []byte("manifest")
	sig, err := identity.SignManifest(priv, "example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	good, err := identity.FingerprintOf("example.com", pk)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Check(&mailkey.Proof{PublicKey: pk, Fingerprint: good, Signature: sig}, "example.com", raw); err != nil {
		t.Fatalf("a self-consistent proof must check out: %v", err)
	}

	// The fingerprint of a DIFFERENT key, presented alongside this one.
	otherPk, _ := key(t, 6)
	wrong, err := identity.FingerprintOf("example.com", otherPk)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.Check(&mailkey.Proof{PublicKey: pk, Fingerprint: wrong, Signature: sig}, "example.com", raw); err == nil {
		t.Fatal("a signer fingerprint that the supplied key does not produce must be rejected")
	}
	if err := identity.Check(nil, "example.com", raw); err == nil {
		t.Fatal("an absent proof must not check out")
	}
}

// TestProofRoundTripsThroughHeaders: what WriteProof emits, ReadProof accepts,
// unchanged.
func TestProofRoundTripsThroughHeaders(t *testing.T) {
	pk, priv := key(t, 7)
	raw := []byte("manifest bytes")
	sig, _ := identity.SignManifest(priv, "example.com", raw)
	fp, _ := identity.FingerprintOf("example.com", pk)
	want := &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}

	h := http.Header{}
	identity.WriteProof(h, want)
	got, found, err := identity.ReadProof(h)
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if !bytes.Equal(got.PublicKey, want.PublicKey) || got.Fingerprint != want.Fingerprint || !bytes.Equal(got.Signature, want.Signature) {
		t.Fatal("the proof did not survive the round trip")
	}
	if err := identity.Check(got, "example.com", raw); err != nil {
		t.Fatalf("the parsed proof must still check out: %v", err)
	}
	// The algorithm is named on the wire rather than inferred from a length.
	if v := h.Get(mailkey.HeaderIdentity); !strings.HasPrefix(v, "ed25519:") {
		t.Fatalf("identity field %q does not name its algorithm", v)
	}
	// A nil proof writes nothing — an unsigned domain, not a broken one.
	empty := http.Header{}
	identity.WriteProof(empty, nil)
	if len(empty) != 0 {
		t.Fatalf("a nil proof wrote %v", empty)
	}
	if _, found, err := identity.ReadProof(empty); err != nil || found {
		t.Fatalf("no fields must read as absent, not as an error: found=%v err=%v", found, err)
	}
}

/*
TestPartialProofIsMalformedNotAbsent is the downgrade rule.

"The proof is missing" is a deployment state — a domain that has not adopted
signing, which a client treats as unsigned. "The proof is incomplete" is an
attack or a broken intermediary. If a subset of the fields were read as absence,
an attacker who could strip ONE header would turn a signed domain into an
unsigned one, and the fail-closed behaviour a pin is supposed to provide would
evaporate against the weakest possible tampering.
*/
func TestPartialProofIsMalformedNotAbsent(t *testing.T) {
	pk, priv := key(t, 8)
	raw := []byte("manifest bytes")
	sig, _ := identity.SignManifest(priv, "example.com", raw)
	fp, _ := identity.FingerprintOf("example.com", pk)
	full := &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}

	for _, drop := range []string{mailkey.HeaderIdentity, mailkey.HeaderSigner, mailkey.HeaderSignature} {
		h := http.Header{}
		identity.WriteProof(h, full)
		h.Del(drop)
		p, found, err := identity.ReadProof(h)
		if err == nil {
			t.Fatalf("dropping %s read as found=%v proof=%v — a stripped field must be an error", drop, found, p)
		}
		if found {
			t.Fatalf("dropping %s reported found", drop)
		}
	}
}

// TestDuplicateProofFieldsAreRejected: two instances let a verifier and an
// attacker read different values from one response, so the field is not
// "the first one" — it is invalid.
func TestDuplicateProofFieldsAreRejected(t *testing.T) {
	pk, priv := key(t, 9)
	raw := []byte("manifest bytes")
	sig, _ := identity.SignManifest(priv, "example.com", raw)
	fp, _ := identity.FingerprintOf("example.com", pk)

	for _, dup := range []string{mailkey.HeaderIdentity, mailkey.HeaderSigner, mailkey.HeaderSignature} {
		h := http.Header{}
		identity.WriteProof(h, &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig})
		h.Add(dup, h.Get(dup)) // the SAME value twice — still invalid
		if _, _, err := identity.ReadProof(h); err == nil {
			t.Fatalf("a duplicated %s was accepted", dup)
		}
	}
}

/*
TestNonCanonicalProofEncodingsAreRejected: one spelling per value.

base64 leaves the last character's unused low bits free, so the same bytes have
several encodings. Mail-Key-Signer is compared against a locally computed
fingerprint; a second spelling of the right bytes would read as the wrong signer
and turn a valid proof into an alarm. This is F-12 in a new place, and it is
closed the same way — the input must re-encode to itself.
*/
func TestNonCanonicalProofEncodingsAreRejected(t *testing.T) {
	pk, priv := key(t, 10)
	raw := []byte("manifest bytes")
	sig, _ := identity.SignManifest(priv, "example.com", raw)
	fp, _ := identity.FingerprintOf("example.com", pk)
	proof := &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}

	base := http.Header{}
	identity.WriteProof(base, proof)

	// A padded spelling, a truncated value, a wrong-length value and an
	// alternative final character all have to be refused.
	bad := map[string]string{
		"padded signer":     base64.URLEncoding.EncodeToString(fp[:]),
		"truncated signer":  manifest.EncodeID(fp)[:20],
		"non-base64 signer": strings.Repeat("!", 43),
		"std-alphabet signer": base64.StdEncoding.WithPadding(base64.NoPadding).
			EncodeToString(bytes.Repeat([]byte{0xfb}, 32)),
	}
	for name, v := range bad {
		h := http.Header{}
		identity.WriteProof(h, proof)
		h.Set(mailkey.HeaderSigner, v)
		if _, _, err := identity.ReadProof(h); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	// The identity field must carry its algorithm prefix and the exact key size.
	for name, v := range map[string]string{
		"no prefix":    manifest.EncodeID(mailkey.Fingerprint(fpOf(pk))),
		"wrong prefix": "ed448:" + manifest.EncodeID(mailkey.Fingerprint(fpOf(pk))),
		"prefix only":  "ed25519:",
	} {
		h := http.Header{}
		identity.WriteProof(h, proof)
		h.Set(mailkey.HeaderIdentity, v)
		if _, _, err := identity.ReadProof(h); err == nil {
			t.Fatalf("identity %q was accepted", name)
		}
	}

	// A signature of the wrong length.
	h := http.Header{}
	identity.WriteProof(h, proof)
	h.Set(mailkey.HeaderSignature, manifest.EncodeID(fp)) // 32 bytes, not 64
	if _, _, err := identity.ReadProof(h); err == nil {
		t.Fatal("a 32-byte signature was accepted")
	}
}

func fpOf(pk ed25519.PublicKey) [32]byte {
	var out [32]byte
	copy(out[:], pk)
	return out
}
