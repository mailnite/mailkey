# Domain Identity Keys and Signed Encryption Epochs (MKDP1-ID)

Status: Draft 0.3
Date: 2026-08-01
Extends: 02-MKDP1-PROTOCOL.md, 03-PEERS-AND-RESOLUTION.md, 04-SECURITY.md

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used as
normative requirements.

## 1. What this closes

04-SECURITY.md §6 states the limitation this document removes:

> Without a separate pinned application signing key, MKDP1 cannot distinguish an
> authorized HTTPS rotation from malicious behavior by a compromised HTTPS
> authority. This is an accepted MKDP1 limitation.

MKDP1 authenticates every fetch with WebPKI and nothing else. A misissued
certificate, or control of the authority host, therefore substitutes any key at
any time, silently and repeatedly.

This extension separates two things MKDP1 conflates:

```text
domain identity          long-lived, Ed25519, signs
encryption epoch         short-lived, X25519, is signed
```

A sender that has once obtained a domain's identity key can verify every later
encryption key without trusting the authority again. The trust the authority
carries drops from *every message* to *first contact*.

It does NOT remove bootstrap trust. A sender meeting a domain for the first time
still depends on WebPKI (optionally corroborated by DNS, or by an administrator).
That is the same bargain SSH makes, and it is stated here rather than implied.

The result is three layers with three different rhythms:

```text
manifest response      short-lived X25519 key + Ed25519 proof
identity resource      rare, long-lived identity and rotation chain
DNS / header fp        corroboration and alerting only
```

## 2. Identity key

A domain MAY publish exactly one ACTIVE identity key.

- The algorithm is Ed25519 (RFC 8032).
- The identity private key MUST NOT be the X25519 encryption key, or derived
  from it. Curve equivalence makes reuse possible and it MUST NOT be done: it
  destroys domain separation between signing and key agreement, and it prevents
  holding the two under different custody.
- The identity key SHOULD be held under stronger custody than encryption keys.
  Signing occurs per epoch, never per message, so an HSM or KMS round trip is
  affordable here — unlike the per-message path, which MKDP1 deliberately keeps
  in process memory.

### 2.1 Fingerprint

The fingerprint `fp` binds the key to its interpretation, exactly as `kid` binds
an encryption key:

```text
fp = SHA256(canonical({
    "type":   "mailkey-domain-identity-v1",
    "domain": <normalized domain d>,
    "alg":    "ed25519",
    "pk":     <32-byte identity public key>
}))
```

`canonical` is the same canonical MessagePack encoding MKDP1 uses everywhere
(sorted keys, exact value kinds, minimal encoding).

The domain and algorithm are inside the preimage so that one raw public key
cannot present the same identity across two domains, and cannot be reinterpreted
under another algorithm.

`fp` is a full 32-byte digest. On the wire it is unpadded base64url. It MUST NOT
be truncated (04-SECURITY.md §8).

## 3. Signed manifest

The identity key signs a domain-separated transcript:

```text
signature_input = "mailkey/mkdp/manifest-signature/v1"
               || <normalized domain d>
               || <exact raw manifest bytes>
```

The fixed context string prevents a signature produced for one MKDP1 object from
verifying as another, and prevents cross-protocol reuse of the identity key
(RFC 8032 §8.4 recommends constant context strings for exactly this). The domain
is included explicitly so a proof cannot be lifted between authorities that
happen to serve identical bytes.

The signed bytes are the EXACT manifest bytes the authority served — the same
bytes `manifest_id` is computed over. The manifest already carries protocol
version, domain, `issued_at`, `expires_at`, the `kid`, the X25519 public key,
the key algorithm and the envelope suite, so signing the whole object covers
every field this extension needs to authenticate. Nothing is signed twice and
nothing signed is left out.

A verifier MUST check, in this order:

1. the manifest parses canonically and validates (02-MKDP1-PROTOCOL.md §5);
2. the supplied identity public key hashes to the supplied `fp` (§2.1);
3. `fp` is the pinned identity for this domain, or is being established (§6);
4. the signature verifies over `signature_input` under that public key;
5. the manifest's `domain` equals the domain being resolved.

A manifest that fails any step MUST NOT install a key.

## 4. Transport

The current manifest parser requires an EXACT field set (`manifest.go`
`exactKeys`: version, domain, issued_at, expires_at, key) and rejects an object
carrying any additional field. Embedding a signature inside the manifest map
would therefore be rejected by every deployed client. The proof is DETACHED, and
the manifest bytes are unchanged — `manifest_id` keeps its value and meaning.

### 4.1 Manifest response

```text
GET https://mail.<d>/.well-known/mail-key

Content-Type: application/msgpack
Mail-Key-Identity:  ed25519:<identity public key, unpadded base64url>
Mail-Key-Signer:    <fp, unpadded base64url>
Mail-Key-Signature: <64-byte Ed25519 signature, unpadded base64url>

<unchanged canonical MKDP1 manifest>
```

Deployed clients ignore the fields and validate the body exactly as today. New
clients verify and pin. The identity public key rides along (44 characters) so
the common case costs no extra request.

Normative rules for the proof fields:

- They are response header fields, never trailers.
- EXACTLY ONE instance of each is allowed.
- All three MUST be present, or the proof is absent. A subset is MALFORMED, not
  absent, and MUST be treated as an invalid proof.
- Duplicate, comma-combined, oversized, or noncanonical values are invalid. Each
  value MUST be canonical unpadded base64url of the exact expected length
  (32/32/64 bytes) and MUST re-encode to itself.
- `Mail-Key-Signer` MUST equal the fingerprint the verifier computes locally
  from `Mail-Key-Identity` (§2.1). A server-supplied fingerprint is never
  trusted as a value, only as a claim to check.
- The fields are end-to-end. They MUST NOT be listed in `Connection` and MUST
  NOT be treated as hop-by-hop.
- The identity public key MUST NOT be accepted from DNS or from email headers.
  Only the HTTPS response may carry key material.

A single RFC 8941 structured field would remove partial-header ambiguity by
construction:

```text
Mail-Key-Proof: alg=ed25519, pk=:<b64>:, fp=:<b64>:, sig=:<b64>:
```

An implementation MAY emit this form in addition. Three separate fields remain
safe provided the exact-cardinality rules above are enforced; a future MKDP2
SHOULD prefer the structured field.

### 4.2 Identity resource

The rotation chain is served separately, because its change frequency is years
rather than days:

```text
GET https://mail.<a>/.well-known/mail-key-identity?d=<d>
Content-Type: application/msgpack
```

`a` is an authority already eligible under MKDP1 §4: `d` during unpinned
bootstrap, and an observed delegated authority only after a pin or separate
authenticated policy authorizes that route. The subject rides as `?d=` here for
exactly the reason it does on the manifest plane — one authority host serves
many domains — and the same server rules apply.

The body is a canonical object carrying the active identity key, its `fp`,
status, an OPTIONAL `authority` sequence, and the ordered chain of rotation
statements (§5). A client fetches it only after a pin exists, to follow a
rotation or check revocation — never to bootstrap trust and never per manifest
refresh.

`authority` carries the same shape, bounds (1..4 canonical domains) and absence
rule as the manifest's (MKDP1 §6), and a client MUST enforce it as a routing
consistency check: the host the document was fetched from must be `mail.<x>`
for some `x` it names, or `mail.<d>` when it names none. The head document has
no document-level signature, so this field MUST NOT authorize delegation; only
the pre-existing pin makes the route eligible, and only signed chain statements
authorize identity transitions.

The identity resource cannot establish its own right to be fetched. Treating
its `authority` field as such a grant would recreate the circular first-contact
trust problem on the identity plane.

Old clients never request this resource, so it MAY use a new strict canonical
schema without any compatibility constraint from MKDP1.

Splitting the two is deliberate. Putting the chain in the manifest response
would make a long-lived object as chatty as a short-lived one; putting the
per-manifest signature in the identity resource would make a long-lived object
change on every re-issue and destroy its cacheability.

### 4.3 Intermediaries

Proxies are required to forward unknown header fields and caches to retain
unrecognized response fields (RFC 9110, RFC 9111), but explicitly configured
intermediaries may still remove them. An operator fronting the authority MUST
ensure the proof fields pass through.

A client that receives an unsigned manifest for an UNPINNED domain MUST treat it
as an unsigned domain (§6), not as an error — stripping and non-adoption are
indistinguishable. For a PINNED domain, a stripped proof is indistinguishable
from an attack and MUST be treated as one (§6.2).

### 4.4 Atomic publication

The body and its proof are ONE immutable publication snapshot:

```text
publishedManifest {
    raw_manifest
    manifest_id
    identity_public_key
    identity_fp
    signature
    expires_at
}
```

The snapshot MUST be generated and cached atomically. A request handler MUST
obtain one snapshot and serve all of its components together. It MUST NOT read
the manifest and the current identity independently.

This requirement also removes a defect that exists without any signing: a
publisher that checks its cache and then builds outside one critical section can
have two concurrent requests each build a manifest, producing two different
`manifest_id` values for the same key at the same instant. Receivers observing
both see an authority alternating between valid manifests — the exact condition
03-PEERS-AND-RESOLUTION.md flags as instability — caused by the publisher rather
than by an attacker. With detached proofs the same race becomes a verification
failure, because the body would come from one build and the proof from another.

For caches:

- `ETag` SHOULD be the manifest id.
- Proof fields MUST be cached with the response.
- A cached proof is reusable ONLY with the exact cached body it authenticated.
- If conditional requests are introduced later, a `304` MUST NOT cause proof
  fields from one body to become associated with another.

## 5. Identity rotation

DNS disagreement MUST NOT rotate a pin. A legitimate identity change is an
authenticated transition:

```text
rotation = {
    "type":       "mailkey-identity-rotation-v1",
    "version":    <protocol version>,
    "domain":     <normalized domain>,
    "old_fp":     <fingerprint being replaced>,
    "new_fp":     <fingerprint taking effect>,
    "new_alg":    "ed25519",
    "new_pk":     <32-byte new identity public key>,
    "not_before": <int64 Unix seconds>,
    "created_at": <int64 Unix seconds>,
    "expires_at": <int64 Unix seconds>
}
```

The statement is signed TWICE over
`"mailkey/mkdp/identity-rotation/v1" || canonical(rotation)`:

- `old_signature` — by the OLD identity key, authorizing the transition;
- `new_signature` — by the NEW identity key, proving possession of the new
  private key.

A verifier MUST require both. The old signature alone would let a stolen old key
install an attacker's identity; the new signature alone would let anyone claim a
succession.

A client MAY accept a new identity ONLY through:

- a valid old→new transition chaining from its current pin;
- an explicit administrator override;
- the recovery process of §8.

Validation starts from the locally pinned `old_fp` and walks forward. HTTPS
transports the chain; the signatures, not HTTPS, authorize each transition.

Ordering comes from the signatures and `not_before`, never from comparing
fields. The `seq` failure MKDP1 was created to remove was not that a counter
existed but that it was UNAUTHENTICATED; a chain whose every link is signed by
the pinned identity is a different construction and MUST NOT be reduced to a
value comparison.

### 5.1 Revocation

A revocation statement uses the same construction with
`"type": "mailkey-identity-revocation-v1"` and a `reason`, signed by the
identity being revoked or by its successor. A revocation MUST remain servable
after the revoked identity's manifests have expired: "stop using this" has to
outlive the thing it refers to.

### 5.2 Bounding the chain

A chain can grow without bound, so an implementation MUST adopt one of:

- a strict maximum entry count and byte size, where rotations are expected to
  stay rare;
- immutable transition lookup by fingerprint;
- a bounded head resource plus linked historical transition objects.

The last is RECOMMENDED:

```text
/.well-known/mail-key-identity            head: active identity + recent chain
/.well-known/mail-key-identity/by-fp/<new-fp>   immutable transition object
```

The head SHOULD use moderate caching with an `ETag`. Immutable transition
objects SHOULD use a long `max-age` with `immutable`.

## 6. Sender rules

### 6.1 Establishing a pin (first contact)

DNS corroboration is unauthenticated and still valuable: it forces an attacker
holding only the TLS path to also manipulate the observed DNS channel before a
false pin becomes persistent. DNSSEC strengthens this materially (RFC 4033
provides origin authentication and integrity, though not availability) and an
implementation SHOULD record the DNSSEC validation status alongside the
observation.

Where pinning is withheld, the operator MUST be told precisely what happened,
because the message IS still encrypted — to a key the attacker may hold:

> Message encrypted using a WebPKI-authenticated but unpinned identity. DNS
> advertised a different identity. Persistent pinning was withheld.

Two states MUST be persisted independently:

```text
EverHTTPSValidated = true          // downgrade protection is now active
IdentityStatus     = contested     // long-term trust was withheld
```

### 6.2 The complete matrix

| Peer state | Proof state | Behavior |
|---|---|---|
| Unpinned | No proof | Legacy WebPKI behavior; do not pin |
| Unpinned | Partial or invalid proof | Legacy encryption; do not pin; alert |
| Unpinned, DNS `fp` present | Proof absent | Legacy encryption; alert possible stripping or misconfiguration |
| Unpinned, DNS matches a valid proof | — | Encrypt and PIN the signer; record DNS as corroboration |
| Unpinned, DNS disagrees | Valid proof | Encrypt with the WebPKI manifest; DO NOT pin; record contested; alert loudly |
| Pinned | Valid proof from the pin | Accept the manifest |
| Pinned | Proof absent or invalid | Reject the response; use a valid cached signed manifest, else HOLD |
| Pinned | Valid proof from another signer | Fetch the rotation chain; reject until authorized |
| Pinned | DNS disagrees | Keep the pin; alert; DNS does not affect delivery |

A successful HTTPS retrieval sets `EverHTTPSValidated = true` even when the
manifest was unsigned and even when pinning was withheld. Consequently an
unpinned or contested peer MUST NOT fall back to plaintext during a later
discovery outage (04-SECURITY.md §7).

A refusal in the pinned rows originates in the established application pin, not
in an unauthenticated observation, so it remains consistent with §7: DNS can
still neither install a key nor create a fail-closed policy.

### 6.3 The residual compatibility property

An attacker who strips the proof from the FIRST interaction can prevent a pin
from ever being established. They cannot force plaintext, and they cannot
replace an established pin. They can only hold the relationship at legacy
WebPKI security — which is where MKDP1 is today.

Once a sender has successfully pinned, stripping becomes fail-closed. This
asymmetry is inherent to opportunistic adoption and is stated rather than
hidden; DNS corroboration (§6.2 row 4) and administrator pinning are the
available answers for a relationship that must not start weak.

### 6.4 Replay protection

Signatures prevent unauthorized manifests. They do not by themselves prevent
REPLAY of an older, still-valid signed manifest — an attacker who can serve
responses may return yesterday's authorization instead of today's.

An implementation MUST persist, per identity:

```text
last_verified_issued_at
last_verified_manifest_id
```

and then:

- the signer MUST first be authorized by the §6.2 identity matrix (including an
  authorized rotation when the signer changed); replay fields are ordering
  evidence and MUST NOT authenticate or bypass a signer;
- an older `issued_at` than the effective manifest is a ROLLBACK alert and MUST
  NOT replace the newer effective manifest;
- two different `manifest_id` values carrying the same `issued_at` are an
  authority-instability alert and the newly fetched manifest MUST NOT replace
  the effective manifest;
- an expired manifest is never eligible for new encryption;
- a valid cached manifest wins over an older, expired, or same-time ambiguous
  HTTPS response; without a usable cache the sender MUST hold rather than use
  the refused response.

A later protocol version MAY add a signed monotonic epoch or a signed
`previous_manifest_id`. The detached bridge MUST NOT add an unsigned sequence
header: an unauthenticated ordering value is the defect MKDP1 exists to avoid.

## 7. DNS advertisement

```text
_mailkey.<d>  IN TXT  "v=MKDP1; fp=<identity fingerprint>; mode=https"
```

During transition a record MAY carry both:

```text
"v=MKDP1; id=<manifest id>; fp=<identity fingerprint>; mode=https"
```

The deployed parser accepts this unchanged: unknown parameters are ignored, and
`fp` is not in the forbidden set (`url, host, port, path, endpoint, pk, key,
seq`). That prohibition is also why the record carries a FINGERPRINT and never
the identity public key — DNS may corroborate an identity, never supply one.

Parsing semantics:

- `fp` is normalized and retained as an OBSERVATION.
- Legacy `id` is accepted and recorded but does not constrain the signer.
- If both appear they are INDEPENDENT observations.
- Neither installs an identity or a manifest.
- `pk`, `key`, and target, port, URL or sequence fields remain forbidden.
- A malformed `fp` makes that RECORD malformed. It MUST NOT silently degrade to
  "no fingerprint".

`id=` is DEPRECATED for new publications. It changes on every manifest re-issue
(`issued_at`/`expires_at` are inside the hashed bytes), so a published record is
stale within days of being written, which both defeats its purpose and, in
implementations that refresh on disagreement, produces one authority fetch per
message. `fp` changes only during identity rollover — not during ordinary
X25519 rotation, and not during manifest renewal.

An implementation MUST NOT alert on a stale `id`. It SHOULD alert on an `fp`
mismatch (§6): the record must carry only values whose change is rare and
meaningful, because an alert that fires routinely is an alert that gets ignored.

## 8. Recovery

Pinning is simple to implement and severe to operate. An implementation MUST
provide all three of:

- **Custody.** The identity private key is a sealed secret of the server,
  carried by the same recovery artifact as its other keys. It MUST NOT become a
  separate thing an operator has to remember.
- **Pre-signed succession.** A planned identity change SHOULD publish an
  old→new rotation (§5) BEFORE the old key is retired, so correspondents follow
  it without human action.
- **Break-glass.** A sender-side administrator action that clears a pin and
  re-establishes it, with an audit record of who did it and what changed.

Without these, one lost identity key permanently breaks a domain's
correspondence with everyone who pinned it.

## 9. Publisher self-check

A domain SHOULD verify its own advertisement rather than discovering a mistake
through its correspondents. The check compares FOUR values:

```text
local configured identity fp        what this server is configured to sign with
fp attached to the local response   what its own handler actually serves
fp returned through external HTTPS  what the world's fetch returns
fp observed in public DNS           what the world's resolvers see
```

It runs before activating a new identity and periodically afterward, queries the
authoritative nameservers AND at least one external recursive path (so a local
cache or split-horizon view cannot create false confidence), records the DNSSEC
validation status, and MUST NOT edit DNS automatically or treat DNS as
authority.

The dashboard SHOULD distinguish: configured identity, published external
fingerprint, DNSSEC validation status, current HTTPS signer, pending rotation,
and the last successful external check.

## 10. Key lifecycle

### 10.1 Three cryptoperiods, three reasons

```text
manifest lifetime      authorization freshness    days
X25519 cryptoperiod    exposure / usage budget    volume- and age-bounded
Ed25519 lifetime       persistent domain identity years, incident-driven
```

A short manifest lifetime MUST NOT imply a new encryption key. Re-issuing a
manifest for the SAME key is the normal case:

```text
Manifest 1:  kid = K   issued day 0   expires day 5
Manifest 2:  kid = K   issued day 4   expires day 9
```

Same key, same `kid`, same signing identity, new timestamps, new `manifest_id`.
DNS `fp` does not change and no peer pin changes. Only the authorization lease
was renewed.

### 10.2 X25519 rotation policy

A receiver SHOULD rotate its X25519 key when the FIRST of these is reached:

```text
successful_decryptions >= max_messages
decrypted_bytes        >= max_bytes
key_age                >= max_age
compromise suspected
administrator requests rotation
```

Volume alone is insufficient, because an inactive key would otherwise stay
authorized indefinitely; age alone is insufficient, because a busy key
accumulates exposure faster than the clock.

An implementation MUST also enforce:

```text
minimum_key_age
maximum_rotations_per_day
one in-flight rotation per domain
```

The minimum age is a security control, not tidiness: without it an attacker who
can send encrypted mail can force continuous rotation, exhausting retention and
denying service.

NIST SP 800-57 Part 1 treats cryptoperiods as bounded by time OR by the amount
of protected data; both bounds limit different aspects of exposure.

### 10.3 Sent and received are not symmetric

The domain's static X25519 key is used when RECEIVING:

```text
remote sender ephemeral X25519  ×  our static domain X25519  →  per-message AEAD key
```

When sending, the local server uses a fresh ephemeral against the PEER's static
key:

```text
fresh local ephemeral X25519  ×  remote peer static X25519  →  per-message AEAD key
```

Therefore:

- successfully received and decrypted messages consume the LOCAL key's budget;
- sent messages consume the REMOTE peer key's budget, not the local one;
- the outbound ephemeral private key is generated per envelope and discarded, so
  it is never rotated.

For outbound accounting an implementation SHOULD keep per-peer statistics
(`messages_sealed_to_peer_kid`, `bytes_sealed_to_peer_kid`, `last_used_at`).
Crossing an outbound threshold MAY trigger a proactive HTTPS refresh; it MUST
NOT be treated as authority to rotate the remote key. Only the receiving domain
can rotate its own key.

### 10.4 Why volume, and why it is not an AEAD limit

MKDP1 derives a fresh AEAD key from a fresh ephemeral per message, so AES-GCM
usage and nonce limits do not accumulate under one long-lived symmetric key.
This is the single-shot shape HPKE describes (RFC 9180): one encapsulation, one
context, one ciphertext.

Rotating the static receiver key by volume therefore bounds something else
entirely:

- the number of historical messages exposed if that private key is later stolen;
- the number of ECDH operations performed under one key;
- the operational blast radius of a compromise;
- the useful lifetime of accidentally copied or leaked key material.

### 10.5 Prerequisite: rotation may not precede shared accounting

> Volume-based X25519 rotation MUST remain disabled until usage counters are
> durable, shared across replicas, and the current-key transition is protected
> by a linearizable compare-and-swap on `current_kid`.

Until then the counters of §10.6 are TELEMETRY. They may be displayed and
alerted on; they MUST NOT change a key. A fleet whose replicas each hold their
own counters would otherwise rotate once per replica for a single threshold
crossing.

### 10.6 Storage layout and the transition CAS

The current-key POINTER is stored apart from the generations it names, and
apart from usage:

```text
domain/<domain>/current-kid   → K
domain/<domain>/key/<K>       → wrapped generation and lifecycle
domain/<domain>/usage/<K>     → messages, bytes
```

Two properties follow from the split. Keying usage by `kid` means a late
delivery to a RETIRED key increments that key's counters and cannot disturb its
successor's budget — the accounting follows the key that actually performed the
ECDH. And because rotation touches only the pointer, the transition needs no
read-modify-write of a record that also carries key material.

Installation is ordered and guarded:

1. write `key/<K2>` — the generation record, so the pointer can never name a
   key that does not exist;
2. then, in ONE linearizable operation:

```text
compare current-kid == K
then    current-kid = K2
else    discard candidate K2
```

The comparison and the successful update MUST be applied atomically — the
standard CAS transaction shape (etcd's transaction model is the reference
implementation of it). Several replicas may reach the threshold together; only
one may win, and the losers MUST discard their candidate key rather than retry
into a second rotation.

### 10.7 The threshold is a soft trigger

The volume threshold bounds compromise exposure; it is not an exact
cryptographic ceiling, and an implementation MUST NOT present it as one:

- duplicate delivery may increment twice;
- a crash may delay or lose an increment;
- concurrent messages may carry the count slightly past the threshold;
- only one rotation wins the pointer CAS, so a simultaneous crossing rotates
  once, not N times.

This is acceptable because every message already derives its own AEAD key
(§10.4): the counter limits how much history one stolen private key exposes,
not how much data one symmetric key protects. An implementation that ever needs
an exact ceiling MUST additionally deduplicate accounting by authenticated
envelope or message identity.

### 10.8 Receiver-side accounting

An implementation SHOULD persist, per key generation:

```text
kid
created_at
first_published_at
last_published_until
successful_decryptions
decrypted_ciphertext_bytes
retired_at
retention_until
status
```

A counter MUST be incremented only after:

1. canonical envelope parsing succeeds;
2. the recipient domain and `kid` select this key;
3. AEAD authentication succeeds.

Malformed or forged-marker messages MUST NOT advance the counter — otherwise
anyone can drive another server's rotation policy with garbage.

Counter updates MAY be asynchronous. Rotation MUST use an atomic
compare-and-swap against the current `kid`:

```text
if current_kid == expected_kid and threshold_reached:
    install newly generated key
```

so that two replicas cannot rotate independently and simultaneously.

### 10.9 Rotation publication order

1. generate the new X25519 key pair;
2. durably store and wrap the private key;
3. build the new manifest;
4. sign it with the identity key;
5. atomically publish body and detached proof (§4.4);
6. mark the previous X25519 key retired;
7. retain the previous private key until its deletion deadline.

The deletion deadline is computed from the key's OWN last published
authorization, not from a global setting:

```text
retention_until = last_published_manifest_expiry
                + maximum_delivery_delay
                + clock_skew_and_operational_margin
```

Messages may legitimately arrive under a retired `kid` after rotation, because
remote senders may hold an unexpired cached manifest naming it.

### 10.10 Identity key policy

The identity key MUST NOT rotate on message volume. It signs manifests, not
messages. Rotate it only for: suspected compromise, algorithm migration,
scheduled long-term hygiene, KMS/HSM migration, or administrative ownership
change.

### 10.11 The resulting hierarchy

```text
Ed25519 identity          years, incident-driven
X25519 receiver key       hybrid max-age + received-volume budget
signed manifest           short authorization lease (e.g. five days)
outbound ephemeral X25519 one envelope
```

## 11. The three identifiers

```text
fp           persistent peer trust anchor   years         pinned; published in DNS
kid          encryption-key selection       per rotation  in envelopes; private-key lookup
manifest_id  exact provenance and audit     per re-issue  never a trust decision
```

An implementation MUST NOT use `manifest_id` as a peer identity, and MUST NOT
choose a key by comparing any of the three.

## 12. Implementation phasing (non-normative)

**P0 — identity signing.** Ed25519 identity and custody, `fp`, signed
manifests, the detached-proof transport with its cardinality rules, atomic
publication (§4.4), interop vectors, and the independent implementation's
verification path. Manifest re-issue reuses the same X25519 key. Rotation stays
manual, incident-driven, and bounded by a conservative maximum age only.

**P0b — sender side.** Pin state, the §6 matrix, replay protection, downgrade
protection, and the Peers UI showing the fingerprint and rotation chain.

**P1 — shared custody.** One shared encrypted keyring for the cluster, no
per-replica key state, replica-safe key GENERATION, and the transactional
current-key pointer of §10.6.

**P2 — durable lifecycle accounting.** Shared counters keyed by
`(domain, kid)`, atomic increments on successful decryption, counter recovery
across restarts, usage visible to every replica. Volume-triggered rotation is
enabled only after this is verified in place — §10.5.

**P3 — rotation and recovery.** Rotation and revocation statements, the identity
resource and its bounding, recovery and break-glass, publisher self-check.

**P4 — enforcement and operator interaction.** Everything above decides what is
TRUE. This phase decides what happens to a message when the answer is bad, and it
is last because the earlier phases are what keep its false-positive rate low
enough to be acceptable.

*The downgrade latch (C-02).* `EverHTTPSValidated` MUST be persisted separately
from observations and from administrator policy, and a peer carrying it that has
no usable manifest MUST fail closed with `ErrEncryptionRequired` rather than send
in the clear. Today that guarantee is documented on `ResolveForEncryption` but
enforced only under `PolicyRequire`, so an attacker who waits for a cached
manifest to expire and then disrupts the refresh returns an established peer to
plaintext. Only an explicit administrator "disable MKDP1 for this domain"
operation may clear the latch; `Forget` MUST preserve it, which means it cannot
live in the record `Forget` deletes.

*Actions are per channel, because the channels differ in who can answer.* One
pure mapping from `(verdict, channel capability, per-domain policy, global
default)` to an action — proceed, defer, reject, ask — with `ask` producible only
on an interactive channel. Defaults MUST prefer deferral to rejection: an
attacker who can strip a header should be able to delay mail, never destroy it,
which is the same reasoning that made the fail-closed outbound path answer 451.

*Proceeding is not one thing.* For an identity refusal, "proceed" means encrypting
to a WebPKI-authenticated manifest without honouring the pin — legacy MKDP1
security, and a defensible operator choice during rollout. For the latch there is
no key at all, so "proceed" means cleartext; that option MUST NOT be offered as a
per-message override on any channel, only as the separately warned administrator
operation above. A message sent under either form of "proceed" MUST NOT be
recorded or displayed as verified: a protection claim may only rest on something
that authenticates.

*Channels.* Interactive webmail asks at send time, while the sender still has the
message in front of them, and its answers map onto state that already exists —
send this one anyway, do not send, or trust this identity for this domain (an
administrator re-pin). A transactional API returns a distinct error per
action-needed reason and MAY accept an explicit override flag on submission, so
the client chooses its own policy. SMTP submission has only response codes and
takes them from the configured policy. Server-generated mail — vacation replies,
delivery notifications, protocol reports — is a fourth channel with no user and
no useful deferral: a notification that never delivers is a lost notification.

*Refusals MUST be reviewable, per peer.* Every withheld pin, refused response and
held message is a fact about ONE domain, so it belongs on that domain's record
rather than only in a log an operator reads after being told to. An
implementation SHOULD keep a bounded, coalesced issue history per peer — reason
code, first and last seen, count — because the same failure repeats on every
retry and an unbounded list of identical rows is not review, it is noise. The
reason CODE is the part that must be stored: prose describes an incident, a code
lets the surface group them and offer the action that resolves them.

*And they MUST reach an operator*, once per domain per condition rather than once
per message, for the same reason §7 restricts what DNS may carry: an alert that
fires routinely is an alert that gets ignored. Held mail, a pinned domain whose
authority changed signer, and a withheld pin are worth waking someone for. An
unsigned domain is not — it is the majority of the internet.

*What the SENDER and the READER are told.* An implementation SHOULD show, per
message, what actually happened to it — and MUST NOT present confidentiality as
authenticity. A message that arrived sealed was sealed with the receiving
domain's PUBLISHED key, which anyone may use; it proves nobody in between could
read it and proves nothing about who sent it. Any single indicator combining the
two MUST take the weaker of them, and the detail MUST be available: a grade that
averages a strong fact with a weak one reports neither.

*Two operations, not one.* Clearing cached manifests so a domain can be
rediscovered is hygiene and MUST preserve the capability latch. Clearing the
latch is a security decision that re-permits plaintext and MUST be a separate,
explicitly warned action. A single control that does both means the safe
operation silently carries the dangerous one.

A transparency log (the RFC 9162 model) would add detection of split-view
rotation — an authority serving different identities to different senders, which
§6 catches only for those who observe the discrepancy. The statement formats
here are deliberately log-friendly (self-contained, signed, chained, canonically
encoded), but a log is out of scope: its value comes from monitors, and a log
nobody watches detects nothing.
