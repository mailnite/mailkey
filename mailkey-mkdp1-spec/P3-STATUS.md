# P3 — rotation and revocation statements

Status: statements + chain verification SHIPPED. The identity RESOURCE
(`/.well-known/mail-key-identity`), recovery/break-glass and the publisher
self-check remain.

Spec: 07-DOMAIN-IDENTITY.md §5, §5.1, §5.2.

## The construction

`identity.Statement` is one signed link. A rotation and a revocation share a
shape because they answer the same question — may this identity still be
trusted, and what replaces it — and one shape means a verifier walks one chain
instead of reconciling two orderings.

**The double signature is the whole thing.** Each half stops a complete break of
pinning:

- old signature only → a stolen old key installs an attacker's identity, which
  is the exact compromise a rotation is supposed to let a domain recover FROM;
- new signature only → anyone who can serve the resource claims succession, and
  pinning collapses back into trusting the transport.

`VerifyStatement` requires both for a rotation. Teeth-verified in both
directions.

**A revocation needs either.** It is often needed precisely BECAUSE the old key
is gone — stolen, lost, destroyed — so requiring the revoked identity to sign its
own withdrawal would make the case that matters most impossible to express. But
neither is not an authority: an unsigned revocation would let anyone withhold any
domain's identity.

## Verification rules

**The walk starts from the local PIN, never the head.** Walking back from the
head would accept any chain ending wherever the server liked — the transport
deciding the pin, which is the one thing the extension exists to prevent.

**Ordering comes from descent, not from fields.** Each step looks for the
statement whose `old_fp` is the identity currently in effect, so the chain may
arrive in any order, with decoys mixed in, and the result is identical. This is
the difference from the `seq` value MKDP1 removed: a counter anyone can set
orders by assertion; a chain orders by signature.

**`new_fp` is recomputed from `new_pk`.** A statement cannot name one identity
and carry another. The adversary here is a publisher that SIGNS a mismatch, not
a corrupted byte — `SignStatement` exists so that adversary can be built in a
test. My first version of that test passed with the check disabled, because
mutating a signed field only proves the signature covers it.

**A forged link breaks the chain rather than being skipped.** A statement
claiming descent from the current identity that does not verify is not noise to
step over: skipping would mean choosing whichever link verified next, letting an
attacker who can inject one statement steer the walk.

## A flaw found while writing the tests

A lapsed revocation would have silently **un-revoked** the identity. §5.1 says
"stop using this" has to outlive the thing it refers to; a verifier that let one
expire would resurrect trust in a key someone announced was compromised, on a
timer the publisher set before they knew they would need it.

Expiry now lapses a rotation — a plan that did not happen, safe to ignore — and
never a revocation. Only a later signed statement, a successor, ends one.
Teeth-verified.

## Bounding (§5.2)

The strict-maximum form: `MaxChainEntries = 32`, `MaxChainBytes = 64 KiB`,
chosen because rotations are expected to stay rare. A domain that legitimately
rotates more than that within one pin's lifetime has an operational problem no
verifier should paper over.

The RECOMMENDED head-plus-`by-fp` resource layout is the next piece, and belongs
with the identity resource rather than here.
