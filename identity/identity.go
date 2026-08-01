/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package identity is the domain identity key: a long-lived Ed25519 key that
SIGNS a domain's manifests, separate from the short-lived X25519 keys those
manifests carry.

It closes the limitation 04-SECURITY.md §6 records as accepted. Without it,
MKDP1's only authority is WebPKI plus the DNS that points at it, so a client
cannot distinguish an authorized key rotation from a compromised authority — a
successful takeover of the host, the certificate or the DNS lets an attacker
publish a manifest naming their own key and every sender adopts it. With it, a
sender pins a FINGERPRINT the first time it resolves a domain, and afterwards a
manifest signed by anything else is not a rotation, it is an alarm.

Two keys, two jobs, two lifetimes:

	Ed25519 identity  signs manifests           years   rotated only on incident
	X25519 encryption receives sealed mail      days    rotated on volume or age

They MUST NOT be the same key, and one MUST NOT be derived from the other. Curve
equivalence makes it possible, which is exactly why the spec forbids it: reuse
destroys domain separation between signing and key agreement, and it makes it
impossible to hold the two under different custody — which is the whole point of
having a signing key that is touched once per rotation rather than once per
message, and can therefore live in an HSM.
*/
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"go.arpabet.com/value"
	"golang.org/x/xerrors"
)

// FingerprintType is the type tag inside a fingerprint preimage. It names what
// is being hashed, so a digest computed for one kind of object can never collide
// with one computed for another.
const FingerprintType = "mailkey-domain-identity-v1"

// Alg is the only identity algorithm MKDP1 defines.
const Alg = "ed25519"

// ManifestContext is the domain-separation string signed before every manifest.
//
// RFC 8032 §8.4 recommends a constant context for exactly this reason: without
// it, a signature produced over some other structure that happens to share a
// byte prefix could verify as a manifest proof, and an identity key used for two
// purposes could have one purpose's signatures replayed as the other's.
const ManifestContext = "mailkey/mkdp/manifest-signature/v1"

/*
FingerprintOf derives the identity fingerprint: SHA-256 over the canonical
encoding of the key together with the interpretation it is claimed under.

The domain and algorithm are INSIDE the preimage, exactly as they are for a kid.
That is what stops one raw public key from presenting the same identity across
two domains — an attacker who controls example.net cannot point example.com's
pin at their own key by reusing the bytes — and what stops the same key from
being reinterpreted under a different algorithm later.

The digest is never truncated. A fingerprint is a trust anchor a sender keeps for
years; halving it to save wire bytes would halve the collision resistance of the
one value the whole extension rests on.
*/
func FingerprintOf(domain string, pk ed25519.PublicKey) (mailkey.Fingerprint, error) {
	var fp mailkey.Fingerprint
	d, err := discovery.Normalize(domain)
	if err != nil {
		return fp, xerrors.Errorf("identity fingerprint: %w", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		return fp, xerrors.Errorf("identity fingerprint: public key is %d bytes, want %d", len(pk), ed25519.PublicKeySize)
	}
	raw, err := value.Pack(value.SortedMapOf(map[string]value.Value{
		"type":   value.Utf8(FingerprintType),
		"domain": value.Utf8(d),
		"alg":    value.Utf8(Alg),
		"pk":     value.Raw(pk, false),
	}))
	if err != nil {
		return fp, xerrors.Errorf("identity fingerprint: %w", err)
	}
	return mailkey.Fingerprint(sha256.Sum256(raw)), nil
}

/*
transcript is the exact byte string an identity signature covers:

	"mailkey/mkdp/manifest-signature/v1" || <normalized domain> || <manifest bytes>

The manifest bytes are the ones actually served — the same bytes manifest_id is
computed over — so the signature covers every field the manifest carries
(version, domain, issued_at, expires_at, kid, public key, algorithms) without
signing anything twice or leaving anything out.

The domain appears twice: once here and once inside the manifest. That is not
redundancy. Without it, an authority serving byte-identical manifests for two
domains it hosts would produce one signature valid for both, and a proof could be
lifted from one to the other.
*/
func transcript(domain string, rawManifest []byte) ([]byte, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return nil, xerrors.Errorf("identity transcript: %w", err)
	}
	out := make([]byte, 0, len(ManifestContext)+len(d)+len(rawManifest))
	out = append(out, ManifestContext...)
	out = append(out, d...)
	return append(out, rawManifest...), nil
}

// SignManifest produces the detached proof for a domain's manifest bytes.
//
// The caller supplies the EXACT bytes it will serve. Re-serializing a manifest
// to sign it would be a bug with no symptom until a verifier disagreed about one
// byte, which is why the publisher builds its bytes once and treats them as
// immutable from then on.
func SignManifest(priv ed25519.PrivateKey, domain string, rawManifest []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, xerrors.Errorf("sign manifest: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(rawManifest) == 0 {
		return nil, xerrors.New("sign manifest: no manifest bytes")
	}
	msg, err := transcript(domain, rawManifest)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, msg), nil
}

/*
VerifyManifest checks a detached proof against the bytes it claims to
authenticate.

This is deliberately narrow: it answers "did the holder of THIS key sign THESE
bytes for THIS domain", and nothing else. Whether the key is the one this
verifier trusts for the domain is a separate question, answered by the pin store,
and keeping the two apart is what stops a caller from accidentally treating "the
signature is internally consistent" as "the domain is authentic" — the mistake
that makes a self-signed proof look like a verified one.
*/
func VerifyManifest(pk ed25519.PublicKey, domain string, rawManifest, sig []byte) error {
	if len(pk) != ed25519.PublicKeySize {
		return xerrors.Errorf("verify manifest: public key is %d bytes, want %d", len(pk), ed25519.PublicKeySize)
	}
	if len(sig) != ed25519.SignatureSize {
		return xerrors.Errorf("verify manifest: signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	msg, err := transcript(domain, rawManifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pk, msg, sig) {
		return xerrors.Errorf("verify manifest: signature does not verify for %s", domain)
	}
	return nil
}

// Generate creates a new identity key pair.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}
