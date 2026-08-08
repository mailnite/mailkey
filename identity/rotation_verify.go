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
	"golang.org/x/xerrors"
)

/*
Verifying a transition, and walking a chain from a pin.

Two rules do the work, and both are about refusing to let anything but a
signature move a trust anchor.

VALIDATION STARTS FROM THE LOCAL PIN. Never from the head of the chain, never
from the newest not_before, never from whatever the server presented first. A
verifier that walked backwards from the head would accept any chain ending
wherever the server liked, which is the transport deciding the pin — the exact
thing §6 exists to prevent.

ORDERING COMES FROM THE SIGNATURES. Each link must chain from the fingerprint the
previous one established. not_before is a policy gate, not a sort key: sorting by
it would let a statement with a convenient timestamp jump the queue, and MKDP1
removed seq precisely to stop ordering from resting on a value someone else
chooses.
*/

// Chain bounds. §5.2 requires an implementation to adopt a bound; these are the
// strict-maximum form, chosen because rotations are expected to stay rare.
const (
	// MaxChainEntries caps the links a verifier will walk. A domain that
	// legitimately rotates more than this in the lifetime of one pin has an
	// operational problem no verifier should paper over.
	MaxChainEntries = 32
	// MaxChainBytes caps the resource before it is parsed.
	MaxChainBytes = 64 << 10
)

var (
	// ErrChainTooLong is a chain past the §5.2 bound.
	ErrChainTooLong = xerrors.New("identity chain: too many transitions")
	// ErrChainBroken is a link that does not descend from the previous one.
	ErrChainBroken = xerrors.New("identity chain: a transition does not chain from the pinned identity")
	// ErrRevoked reports an identity withdrawn by a valid revocation.
	ErrRevoked = xerrors.New("identity chain: the identity was revoked")
)

/*
VerifyStatement checks one statement's signatures against the keys it names.

oldPK is supplied by the CALLER, from its pin — it is not in the statement, and
that asymmetry is deliberate. A verifier that took the old key from the object it
is verifying would be checking a signature against a key the same server chose,
which authenticates nothing at all.

The new key IS in the statement, because it must be: the whole purpose is to
introduce it. It is bound by requiring new_fp to equal the fingerprint recomputed
from new_pk, so a statement cannot name one identity and carry another.
*/
func VerifyStatement(s Statement, oldPK ed25519.PublicKey) error {
	if s.Type != RotationType && s.Type != RevocationType {
		return xerrors.Errorf("identity statement: unknown type %q", s.Type)
	}
	if s.Version != mailkey.Version {
		return xerrors.Errorf("identity statement: version %q, want %q", s.Version, mailkey.Version)
	}
	msg, err := s.signingBytes()
	if err != nil {
		return err
	}

	// The caller's trusted key must be the identity the statement claims to
	// descend from. WalkChain already selects on OldFP; checking again makes
	// VerifyStatement safe as a public entry point rather than only as an
	// implementation detail of the walker.
	if len(oldPK) != ed25519.PublicKeySize {
		return xerrors.New("identity statement: the currently trusted public key is missing or malformed")
	}
	oldFP, err := FingerprintOf(s.Domain, oldPK)
	if err != nil {
		return err
	}
	if oldFP != s.OldFP {
		return xerrors.New("identity statement: old_fp does not match the currently trusted identity")
	}

	// The new identity, when one is named, must be the one it claims to be.
	if len(s.NewPK) != 0 && len(s.NewPK) != ed25519.PublicKeySize {
		return xerrors.New("identity statement: new_pk is the wrong length")
	}
	if s.NewAlg != Alg {
		return xerrors.Errorf("identity statement: new_alg %q, want %q", s.NewAlg, Alg)
	}
	hasNew := len(s.NewPK) == ed25519.PublicKeySize
	if hasNew {
		want, ferr := FingerprintOf(s.Domain, s.NewPK)
		if ferr != nil {
			return ferr
		}
		if want != s.NewFP {
			return xerrors.New("identity statement: new_fp does not match new_pk — the statement names an identity it does not carry")
		}
	} else {
		var zero mailkey.Fingerprint
		if s.NewFP != zero || len(s.NewSignature) != 0 {
			return xerrors.New("identity statement: successor fields are present without new_pk")
		}
	}

	oldOK := len(s.OldSignature) == ed25519.SignatureSize &&
		ed25519.Verify(oldPK, msg, s.OldSignature)
	newOK := hasNew && len(s.NewSignature) == ed25519.SignatureSize &&
		ed25519.Verify(s.NewPK, msg, s.NewSignature)

	if s.IsRevocation() {
		// Withdrawal and succession are both trust decisions. Only the
		// currently trusted old identity can authorize them. A successor's
		// signature is proof that it possesses NewPK, never permission for an
		// otherwise arbitrary key to introduce itself.
		if !oldOK {
			return xerrors.New("identity revocation: the currently trusted identity did not authorize this statement")
		}
		if hasNew && !newOK {
			return xerrors.New("identity revocation: the successor did not prove possession of its key")
		}
		return nil
	}
	// A rotation requires BOTH. The old signature authorizes the transition;
	// the new signature proves possession. The latter can never replace the
	// former, and neither signature is a recovery mechanism for old-key
	// compromise.
	if !oldOK {
		return xerrors.New("identity rotation: the old identity did not authorize this transition")
	}
	if !newOK {
		return xerrors.New("identity rotation: the new identity did not prove possession of its key")
	}
	return nil
}

// ChainResult is where a verified walk ended.
type ChainResult struct {
	// Fingerprint is the identity now in effect — the caller's pin when nothing
	// applied, or the last one a valid transition established.
	Fingerprint mailkey.Fingerprint
	// PublicKey is that identity's key, empty when the walk never moved.
	PublicKey ed25519.PublicKey
	// Applied is how many transitions were followed.
	Applied int
	// Revoked reports that the identity in effect was withdrawn. Mail must not
	// be sealed to it, and a caller MUST NOT treat this as "no key" — the
	// difference between "we have nothing" and "we were told to stop" is the
	// difference between waiting and acting.
	Revoked bool
	// Reason is the revocation's signed reason, when Revoked.
	Reason string
}

/*
WalkChain follows a domain's identity history from the caller's PIN forward.

Statements are matched by descent, not by order in the slice: at each step the
walk looks for the one statement whose old_fp is the fingerprint currently in
effect. A server may therefore present the chain in any order, or with unrelated
statements mixed in, and the result is the same — because the only thing that
advances the walk is a signature from the key it already trusts.

now gates not_before: a transition the publisher has signed but not yet made
effective is valid and simply does not apply yet. It is skipped, not rejected,
so publishing a rotation ahead of time is a supported operation rather than an
error a verifier reports.
*/
func WalkChain(pin mailkey.Fingerprint, pinPK ed25519.PublicKey, chain []Statement, now time.Time) (ChainResult, error) {
	out := ChainResult{Fingerprint: pin, PublicKey: pinPK}
	if len(chain) > MaxChainEntries {
		return out, xerrors.Errorf("%w: %d entries, max %d", ErrChainTooLong, len(chain), MaxChainEntries)
	}
	used := make(map[int]bool, len(chain))
	for step := 0; step < len(chain); step++ {
		next := -1
		for i, s := range chain {
			if used[i] || s.OldFP != out.Fingerprint {
				continue
			}
			if s.NotBefore.After(now) {
				// Signed but not yet effective. Not an error: a publisher may
				// stage a rotation ahead of time, and a verifier that rejected
				// one would make that a broken chain instead of a plan.
				continue
			}
			/*
				Expiry lapses a ROTATION and never a revocation.

				§5.1: "A revocation MUST remain servable after the revoked
				identity's manifests have expired: 'stop using this' has to
				outlive the thing it refers to." A verifier that let one lapse
				would RESURRECT trust in a key someone announced was
				compromised, and would do it silently, on a timer the publisher
				set before they knew they would need it.

				So the only thing that ends a revocation is a later signed
				statement — a successor — not the clock.
			*/
			if !s.IsRevocation() && !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(now) {
				continue
			}
			if err := VerifyStatement(s, out.PublicKey); err != nil {
				// A statement that CLAIMS to descend from the current identity
				// and does not verify is not something to skip past — it is
				// either a forgery or a corrupted chain, and continuing would
				// mean choosing whichever link happened to verify next.
				return out, xerrors.Errorf("%w: %v", ErrChainBroken, err)
			}
			next = i
			break
		}
		if next < 0 {
			return out, nil // nothing further descends from here
		}
		used[next] = true
		s := chain[next]
		if s.IsRevocation() {
			out.Revoked, out.Reason = true, s.Reason
			if len(s.NewPK) == ed25519.PublicKeySize {
				// VerifyStatement required authorization from the old key and
				// proof of possession from this successor. Only after both may
				// the statement withdraw the old identity and advance the pin.
				out.Fingerprint, out.PublicKey = s.NewFP, s.NewPK
				out.Applied++
				out.Revoked, out.Reason = false, ""
				continue
			}
			out.Applied++
			return out, nil
		}
		out.Fingerprint, out.PublicKey = s.NewFP, s.NewPK
		out.Applied++
	}
	return out, nil
}
