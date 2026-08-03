# P3 — rotation and revocation statements

Status: COMPLETE end to end. Statements, chain verification, the resource
format, the self-check comparison, break-glass AND the wiring: rotation in key
management (one-record CAS holding seed + chain — no crash window between "new
key" and "the transition explaining it"), the resource served on every surface
the manifest is (web ports + dedicated MailKeyServer), the hardened sender-side
fetch, and the peer service following a chain from its pin on signer change —
revocation holds mail and files IssueRevoked. Verified live: the e2e mailkey
suite fetches the resource on both ports; TestRotationLeavesAFollowableTrail
walks operator-rotate → served doc → correspondent pin, twice.

The §5.2 bound adopted is the STRICT-MAXIMUM form (32 entries / 64 KiB), so the
RECOMMENDED by-fp immutable objects are not needed for compliance and are not
served.

The §9 check now runs its DNS half for real — authoritative NS and public
recursors, from a daily sweeper bean plus an on-demand button — with a diagnosis
table (absent / mismatch / split / propagating) whose rows are repairs. The
HTTPS half still needs an out-of-process vantage point (relay probes) and still
reports "not checked externally". The envelope-derived interception detector
(foreign seals) shipped with it.

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


---

## The identity resource (§4.2, §5.2)

`identity.Doc` with `PackDoc` / `ParseDoc`, plus `ByFPPathFor` for the immutable
per-transition objects.

Split from the manifest deliberately. Putting the chain in the manifest response
would make a long-lived object as chatty as a short-lived one; putting the
per-manifest signature here would make a long-lived object change on every
re-issue and destroy its cacheability.

**A STRICT schema, failing closed on unknown fields.** Old clients never request
this resource, so there is no deployed parser to stay compatible with — and the
one thing it must never do is let something be smuggled past a verifier that
shrugged at it. The accessors are duplicated from the manifest package rather
than shared: the manifest's rules are fixed by a deployed wire format, this
resource's are free to be stricter, and that freedom only survives if the two do
not share a definition of "a field".

**`active_fp` is recomputed from `active_pk`**, and **the domain comes from the
CALLER**. Otherwise a document could advertise a fingerprint an operator
recognises while carrying an attacker's key, or be lifted from one domain's
endpoint to another's.

**`by-fp/<fp>` is content-addressed by the fingerprint the transition INSTALLS**,
which is what makes `immutable` caching honest: the object at a path can never
legitimately change, because a different transition installs a different
fingerprint and therefore lives elsewhere.

## Publisher self-check (§9)

`identity.SelfCheck` compares the four values. There are four rather than two
because each adjacent pair fails differently — configured≠served is a deployment
that half-applied, served≠external is something in front of the server,
external≠DNS is an advertisement someone forgot. Comparing only the ends would
find "something is wrong" and nothing about where, which for an operator at 3am
is barely better than hearing it from a correspondent.

External is compared against SERVED, not against configured: if the handler is
serving the wrong thing the external mismatch is a consequence, not a second
fault, and reporting both would send an operator chasing a proxy that is
faithfully relaying a server that is already wrong.

**DNS findings are never blocking.** DNS is corroboration, never authority (§7).
A disagreement withholds pins and is worth showing, but if it blocked activation
then anyone able to disturb a domain's DNS would hold a veto over its key
management — a larger power than the corroboration is worth. Teeth-verified.

## Break-glass (§8)

`admin.peers.repin`: clears a domain's pin so the next resolve establishes a new
one. Required because pinning is "simple to implement and severe to operate" —
a domain that loses its identity key with no pre-signed succession has
permanently broken its correspondence with everyone who pinned it, and without a
remedy the only fix is every correspondent editing their own state.

Three properties make it safe enough to exist:

- **It needs a reason**, like the downgrade authorization. The next operator will
  ask why this domain's anchor was discarded, and the answer should not be
  archaeology. The reason lands in the log and on the peer's issue record.
- **It clears ONLY the pin.** The capability latch survives: "forget what I
  trusted" and "stop requiring encryption" are different decisions, and folding
  the second into the first would hand out a downgrade with every repair.
- **It re-pins on next contact** rather than pinning something named here. An
  operator who could name the new fingerprint is an operator who can be socially
  engineered into naming an attacker's.

## What remains

- **Serving** the resource from mailnite (`/.well-known/mail-key-identity` and
  `by-fp/`), which needs the publisher to hold a chain — i.e. rotation wired
  into key management, not just the statement format.
- **Fetching** it on the sender side and feeding `WalkChain` from the peer store.
- **Running** the self-check: authoritative-NS and external-recursive DNS paths,
  an external HTTPS fetch, a schedule, and the dashboard fields of §9.
- **Custody** (§8): the identity private key riding the existing recovery
  artifact rather than becoming a separate thing to remember.
