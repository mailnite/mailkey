/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity

import (
	"crypto/ed25519"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"go.arpabet.com/value"
	"golang.org/x/xerrors"
)

/*
Identity rotation and revocation statements (spec 07 §5).

A pin is a trust anchor a sender keeps for years, and the whole point of §6 is
that nothing UNAUTHENTICATED may move it — not DNS, not a fresh manifest, not the
absence of one. A legitimate identity change is therefore its own signed object,
and this file is that object and its verification.

The construction that matters is the DOUBLE signature. The old key authorizes the
transition; the new key proves possession. Either alone is a complete break:

  - old only — a stolen old key installs an attacker's identity, which is the
    exact compromise a rotation is supposed to be able to recover FROM;
  - new only — anyone who can serve the resource claims succession, and pinning
    reduces to trusting the transport again.

Ordering comes from the signatures and not_before, never from comparing fields.
The seq failure MKDP1 was created to remove was not that a counter existed but
that it was unauthenticated; a chain whose every link is signed by the key it
descends from is a different construction and is deliberately not reduced to a
value comparison.
*/

const (
	// RotationType tags a transition statement. It is INSIDE the signed bytes,
	// so a signature over one statement kind can never verify as another.
	RotationType = "mailkey-identity-rotation-v1"
	// RevocationType tags a revocation. §5.1: the same construction, a
	// different type, plus a reason.
	RevocationType = "mailkey-identity-revocation-v1"
	// StatementContext is the domain-separation prefix both statements are
	// signed under (§5). One context for both is safe BECAUSE the type is bound
	// inside the canonical bytes: cross-type confusion would require a
	// canonical encoding of a rotation to equal that of a revocation, and the
	// differing "type" value makes that impossible.
	StatementContext = "mailkey/mkdp/identity-rotation/v1"
)

/*
Statement is one signed link in a domain's identity history.

A rotation and a revocation are the same shape because they answer the same
question — "may this identity still be trusted, and what replaces it" — and
keeping them one type means a verifier walks one chain rather than reconciling
two orderings.

NewPK is carried, NewFP is not derived from it by the signer: a verifier
RECOMPUTES the fingerprint from NewPK and rejects a mismatch, so a statement
cannot name a fingerprint its own key does not produce. The same rule the
detached proof uses, for the same reason.
*/
type Statement struct {
	Type      string
	Version   string
	Domain    string
	OldFP     mailkey.Fingerprint
	NewFP     mailkey.Fingerprint
	NewAlg    string
	NewPK     ed25519.PublicKey
	NotBefore time.Time
	CreatedAt time.Time
	ExpiresAt time.Time
	// Reason is present on a revocation and empty on a rotation. It is signed,
	// so an operator reading "key compromise" is reading something the holder of
	// the key actually said.
	Reason string

	// OldSignature is by the identity being replaced or revoked; NewSignature by
	// the one taking effect. A rotation requires BOTH. A revocation requires
	// either, since it may be issued by the revoked identity itself (the
	// ordinary case) or by its successor (when the old key is already gone).
	OldSignature []byte
	NewSignature []byte
}

// IsRevocation reports whether this statement withdraws an identity rather than
// replacing it.
func (s Statement) IsRevocation() bool { return s.Type == RevocationType }

/*
canonical is the exact byte string a statement's signatures cover.

Every field of the statement is inside it, including the type and the domain, and
the signatures are NOT — a signature cannot cover itself. Field names are the
spec's wire names so an independent implementation encoding from the spec text
alone produces identical bytes.
*/
func (s Statement) canonical() ([]byte, error) {
	d, err := discovery.Normalize(s.Domain)
	if err != nil {
		return nil, xerrors.Errorf("identity statement: %w", err)
	}
	m := map[string]value.Value{
		"type":       value.Utf8(s.Type),
		"version":    value.Utf8(s.Version),
		"domain":     value.Utf8(d),
		"old_fp":     value.Raw(s.OldFP[:], false),
		"new_fp":     value.Raw(s.NewFP[:], false),
		"new_alg":    value.Utf8(s.NewAlg),
		"new_pk":     value.Raw(s.NewPK, false),
		"not_before": value.Long(s.NotBefore.Unix()),
		"created_at": value.Long(s.CreatedAt.Unix()),
		"expires_at": value.Long(s.ExpiresAt.Unix()),
	}
	if s.IsRevocation() {
		m["reason"] = value.Utf8(s.Reason)
	}
	raw, err := value.Pack(value.SortedMapOf(m))
	if err != nil {
		return nil, xerrors.Errorf("identity statement: %w", err)
	}
	return raw, nil
}

// signingBytes prefixes the context, exactly as a manifest proof does.
func (s Statement) signingBytes() ([]byte, error) {
	raw, err := s.canonical()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(StatementContext)+len(raw))
	out = append(out, StatementContext...)
	return append(out, raw...), nil
}

/*
SignStatement signs a statement exactly as given, changing none of its fields.

The safe constructors below derive the fingerprints from the keys, which is what
an honest publisher wants. This one does not, because a publisher CAN sign a
statement whose new_fp does not match its new_pk — through a bug, or on purpose —
and a verifier that trusted the field would pin an attacker's key while its logs
showed a fingerprint an operator recognised. Being able to produce that statement
is what lets the verifier's recomputation be tested against the adversary that
actually exists rather than against a corrupted byte.
*/
func SignStatement(s Statement, oldPriv, newPriv ed25519.PrivateKey) (Statement, error) {
	msg, err := s.signingBytes()
	if err != nil {
		return Statement{}, err
	}
	if len(oldPriv) == ed25519.PrivateKeySize {
		s.OldSignature = ed25519.Sign(oldPriv, msg)
	}
	if len(newPriv) == ed25519.PrivateKeySize {
		s.NewSignature = ed25519.Sign(newPriv, msg)
	}
	return s, nil
}

/*
SignRotation builds and signs a transition from oldPriv to newPriv.

Both keys are required, and the function will not produce a half-signed
statement: a rotation missing either signature is not a weaker rotation, it is
one of the two attacks this construction exists to stop, and a builder that could
emit one would eventually be handed one key by a caller who thought that was
enough.
*/
func SignRotation(domain string, oldPriv, newPriv ed25519.PrivateKey, notBefore, createdAt, expiresAt time.Time) (Statement, error) {
	if len(oldPriv) != ed25519.PrivateKeySize || len(newPriv) != ed25519.PrivateKeySize {
		return Statement{}, xerrors.New("sign rotation: both the old and the new private key are required")
	}
	oldPK := oldPriv.Public().(ed25519.PublicKey)
	newPK := newPriv.Public().(ed25519.PublicKey)
	oldFP, err := FingerprintOf(domain, oldPK)
	if err != nil {
		return Statement{}, err
	}
	newFP, err := FingerprintOf(domain, newPK)
	if err != nil {
		return Statement{}, err
	}
	s := Statement{
		Type: RotationType, Version: mailkey.Version, Domain: domain,
		OldFP: oldFP, NewFP: newFP, NewAlg: Alg, NewPK: newPK,
		NotBefore: notBefore, CreatedAt: createdAt, ExpiresAt: expiresAt,
	}
	msg, err := s.signingBytes()
	if err != nil {
		return Statement{}, err
	}
	s.OldSignature = ed25519.Sign(oldPriv, msg)
	s.NewSignature = ed25519.Sign(newPriv, msg)
	return s, nil
}

/*
SignRevocation withdraws an identity.

successorPriv is optional. A revocation issued by the identity itself is the
ordinary case; one issued by a successor exists because the reason for revoking
is often that the old key is no longer usable — and a revocation nobody can issue
is a revocation that never happens.

At least one key is required. A statement with neither signature says "stop
trusting this" on nobody's authority, which is a denial-of-service anyone could
mount against any domain.
*/
func SignRevocation(domain string, revokedPriv, successorPriv ed25519.PrivateKey, reason string, createdAt, expiresAt time.Time, revokedFP mailkey.Fingerprint) (Statement, error) {
	if len(revokedPriv) != ed25519.PrivateKeySize && len(successorPriv) != ed25519.PrivateKeySize {
		return Statement{}, xerrors.New("sign revocation: the revoked identity's key or a successor's key is required")
	}
	s := Statement{
		Type: RevocationType, Version: mailkey.Version, Domain: domain,
		OldFP: revokedFP, NewAlg: Alg,
		CreatedAt: createdAt, NotBefore: createdAt, ExpiresAt: expiresAt,
		Reason: reason,
	}
	if len(revokedPriv) == ed25519.PrivateKeySize {
		revokedPK := revokedPriv.Public().(ed25519.PublicKey)
		fp, err := FingerprintOf(domain, revokedPK)
		if err != nil {
			return Statement{}, err
		}
		s.OldFP = fp
	}
	if len(successorPriv) == ed25519.PrivateKeySize {
		successorPK := successorPriv.Public().(ed25519.PublicKey)
		fp, err := FingerprintOf(domain, successorPK)
		if err != nil {
			return Statement{}, err
		}
		s.NewFP, s.NewPK = fp, successorPK
	}
	msg, err := s.signingBytes()
	if err != nil {
		return Statement{}, err
	}
	if len(revokedPriv) == ed25519.PrivateKeySize {
		s.OldSignature = ed25519.Sign(revokedPriv, msg)
	}
	if len(successorPriv) == ed25519.PrivateKeySize {
		s.NewSignature = ed25519.Sign(successorPriv, msg)
	}
	return s, nil
}
