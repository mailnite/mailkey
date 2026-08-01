/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/textproto"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"golang.org/x/xerrors"
)

// identityPrefix labels the algorithm inside Mail-Key-Identity, so the field
// says what kind of key it carries rather than leaving a verifier to infer it
// from a length.
const identityPrefix = Alg + ":"

/*
Check reports whether a proof is internally consistent: the fingerprint is the
one this public key produces for the domain, and the signature verifies over the
manifest bytes.

Internally consistent is NOT trusted, and the name says so on purpose. A proof
an attacker generated with their own key passes this every time; what makes a
proof meaningful is that its fingerprint is the one the verifier PINS for the
domain, which is a separate decision made against the pin store. Keeping the two
apart is what stops "the signature checks out" from being mistaken for "the
domain is authentic".
*/
func Check(p *mailkey.Proof, domain string, rawManifest []byte) error {
	if p == nil {
		return xerrors.New("proof: absent")
	}
	fp, err := FingerprintOf(domain, p.PublicKey)
	if err != nil {
		return err
	}
	// Constant time is not about secrecy here — everything compared is public.
	// It is about not writing a comparison that a later reader might copy into a
	// place where it does matter.
	if subtle.ConstantTimeCompare(fp[:], p.Fingerprint[:]) != 1 {
		return xerrors.Errorf("proof: the signer fingerprint is not the one this public key produces for %s", domain)
	}
	return VerifyManifest(p.PublicKey, domain, rawManifest, p.Signature)
}

// WriteProof sets the three response fields. A nil proof writes nothing, which
// is the honest representation of a domain that has no identity key yet: the
// manifest is still served and still valid, it simply carries no authentication.
func WriteProof(h http.Header, p *mailkey.Proof) {
	if p == nil {
		return
	}
	h.Set(mailkey.HeaderIdentity, identityPrefix+encodeB64(p.PublicKey))
	h.Set(mailkey.HeaderSigner, manifest.EncodeID(p.Fingerprint))
	h.Set(mailkey.HeaderSignature, encodeB64(p.Signature))
}

/*
ReadProof extracts and structurally validates the proof fields.

found=false means all three were absent — a domain that publishes no identity,
which a client treats as an unsigned domain rather than an error. An error means
they were present and wrong, which is a different thing entirely and must never
be softened into absence: "the proof is missing" is a deployment state, "the
proof is malformed" is an attack or a broken intermediary, and collapsing them
lets a stripped-to-invalid downgrade pass as ordinary.

Every rule here exists because its absence is exploitable:

  - exactly one instance of each, because a duplicated field lets a verifier and
    an attacker read different values from the same response;
  - all three or none, so a subset cannot be silently read as absence;
  - exact decoded lengths, so a truncated key or signature cannot be padded into
    something a lax parser accepts;
  - canonical re-encode, because base64url has multiple spellings of the same
    bytes and a fingerprint that compares as a STRING would then have several
    valid forms (the F-12 defect, in a new place).
*/
func ReadProof(h http.Header) (*mailkey.Proof, bool, error) {
	idv, idn := field(h, mailkey.HeaderIdentity)
	fpv, fpn := field(h, mailkey.HeaderSigner)
	sgv, sgn := field(h, mailkey.HeaderSignature)

	switch {
	case idn == 0 && fpn == 0 && sgn == 0:
		return nil, false, nil // unsigned domain
	case idn > 1 || fpn > 1 || sgn > 1:
		return nil, false, xerrors.New("proof: a field appears more than once")
	case idn == 0 || fpn == 0 || sgn == 0:
		// Deliberately an error, not absence. See the doc comment.
		return nil, false, xerrors.New("proof: incomplete — all three fields are required together")
	}

	if len(idv) <= len(identityPrefix) || idv[:len(identityPrefix)] != identityPrefix {
		return nil, false, xerrors.Errorf("proof: identity must be %q-prefixed", identityPrefix)
	}
	pk, err := decodeExact(idv[len(identityPrefix):], ed25519.PublicKeySize)
	if err != nil {
		return nil, false, xerrors.Errorf("proof: identity key: %w", err)
	}
	fpBytes, err := decodeExact(fpv, 32)
	if err != nil {
		return nil, false, xerrors.Errorf("proof: signer: %w", err)
	}
	sig, err := decodeExact(sgv, ed25519.SignatureSize)
	if err != nil {
		return nil, false, xerrors.Errorf("proof: signature: %w", err)
	}
	var fp mailkey.Fingerprint
	copy(fp[:], fpBytes)
	return &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig}, true, nil
}

// field returns a header's single value and how many instances were present.
// It reads the canonical map directly rather than through Header.Get, which
// silently returns the first of several — the exact ambiguity the cardinality
// rule exists to reject.
//
// A comma-combined value counts as one instance to net/http but is rejected
// later: none of the three fields is list-valued, so a comma cannot decode.
func field(h http.Header, name string) (string, int) {
	vs := h[textproto.CanonicalMIMEHeaderKey(name)]
	if len(vs) == 0 {
		return "", 0
	}
	return vs[0], len(vs)
}

/*
encodeB64 and decodeExact are the ONE spelling rule, applied to every value in
the proof.

base64 leaves the final character's unused low bits free, so the same bytes have
several valid encodings. That cost MKDP1 a real defect once already (F-12, where
one manifest id had multiple spellings), and the consequence here would be worse:
Mail-Key-Signer is compared against a locally computed fingerprint, so a second
spelling of the right bytes would read as the WRONG signer and turn a valid proof
into an alarm — or, for an implementation comparing decoded bytes on one path and
strings on another, the reverse.

Requiring the input to re-encode to itself leaves exactly one spelling.
*/
func encodeB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeExact(s string, want int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, xerrors.Errorf("base64url: %w", err)
	}
	if len(b) != want {
		return nil, xerrors.Errorf("must be %d bytes, got %d", want, len(b))
	}
	if encodeB64(b) != s {
		return nil, xerrors.Errorf("%q is not the canonical spelling of its bytes", s)
	}
	return b, nil
}
