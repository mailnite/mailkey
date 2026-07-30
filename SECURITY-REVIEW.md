# MKDP1 security review

Status: review of Draft 0.1 (`mailkey-mkdp1-spec/`) against the existing
Mailnite/mailcore implementation and the `go.arpabet.com/value` canonical
form. Date: 2026-07-30.

This document is the pre-implementation attack analysis. It states what MKDP1
defends, what it deliberately does not, where the *current* code violates the
spec, and which obligations the reference implementation must carry. Findings
that change code are numbered **F-n**.

---

## 1. What the protocol actually moves

The pre-MKDP1 design (`_mailpubkey` TXT + the DKIM-signed `Mailnite-Key`
header) let **three channels install a public key**: DNS, a verified mail
header, and manual entry — arbitrated by a public `seq` under a
"greatest value wins" rule.

MKDP1 collapses installation to **one authenticated channel** (WebPKI HTTPS at
a deterministic host) and demotes everything else to *observations that cannot
install anything*. That is the whole security thesis, and it is sound: it
converts a multi-authority arbitration problem (where the arbiter was an
attacker-suppliable integer) into a single-authority fetch problem.

The trust anchor changes with it: from *the sending domain's DKIM key* to *the
WebPKI CA set plus the domain's control of `mail.<d>`*. Neither is strictly
stronger than the other — DKIM learning is exposed to DNS spoofing, WebPKI to
CA misissuance — but the number of paths that can write a key drops from three
to one, and that is the property worth having.

---

## 2. Attacker model

| Attacker | Capability | Relevant to |
|---|---|---|
| Off-path spammer | Sends mail with arbitrary headers | header observations, SSRF, DoS |
| DNS spoofer / on-path resolver | Forges `_mailkey` TXT and A/AAAA answers | DNS observations, SSRF target selection, rebinding |
| Network on-path (sender↔recipient) | Modifies SMTP bytes in flight | envelope metadata integrity (**F-1**) |
| Malicious CA / misissuance | Presents a valid chain for `mail.<d>` | accepted limitation (§6) |
| Compromised peer HTTPS host | Serves any manifest it likes | accepted limitation (§6) |
| Local operator error | Pastes the wrong thing into the UI | form only accepts a domain |
| Recipient server itself | Holds the private key | out of scope by design |

---

## 3. Per-attack analysis

### 3.1 Forged sequence number (the motivating attack) — FIXED by design

Old: an observation carrying `seq = 2^63` became "newest" forever; legitimate
rotations were then permanently refused as rollbacks. A single forged
observation could freeze a domain's key — a durable, remote, unauthenticated
denial of rotation.

MKDP1: no public ordering value exists. `issued_at` is explicitly *not* a
selector, and the current HTTPS response is authoritative. The attack has no
input to poison. **This is the single biggest improvement in the protocol.**

Implementation obligation: the ordering machinery in mailnite's pin book
(seq-monotonic `LearnPin`, equal-seq conflict ledger) becomes dead weight — it
must be **removed**, not left alongside MKDP1, or the frozen-rotation bug
returns through the old path.

### 3.2 Forged `Mail-Key` header

Contains no key, so it cannot install one. Residual effects: a false
observation, and a *triggered outbound fetch*. See SSRF below — this is the
one genuinely remote-triggerable code path MKDP1 adds, and it deserves the
most implementation care.

Obligations: never block or delay inbound delivery on it; never let it arm
fail-closed policy; strip locally-submitted `Mail-Key` from outbound mail
before stamping our own (otherwise a hostile local user forges our advert).

### 3.3 Forged DNS advertisement

Same shape, weaker reach: it can only trigger a fetch and record a wrong
observed ID. Without DNSSEC the record is spoofable, which is precisely why
MKDP1 refuses to let DNS carry key material.

### 3.4 SSRF and request amplification — **highest implementation risk (F-3)**

A stranger's email makes *our* server issue an HTTPS request to a hostname
*they* chose the domain part of. Even with the URL constructed internally this
is an unauthenticated outbound-request primitive:

- internal network probing where split DNS exists;
- traffic reflection toward a victim (amplification is only ~1:1 and bounded
  at 16 KiB, but a mail flood multiplies it);
- DNS rebinding: pass validation, then answer with `127.0.0.1`.

Mandatory defenses (all implemented in `resolver`):

1. Derive the URL from a normalized domain; never accept a host, port, path or
   URL from the wire. HTTPS, port 443, no redirects, no proxy auth.
2. Reject IP-literal and non-public domains before any lookup.
3. Validate **every resolved address at connection time** via a custom
   `DialContext` — loopback, private, link-local, unique-local, CGNAT,
   multicast, unspecified and reserved ranges are refused. This is the
   rebinding defense: the check happens on the address actually dialed, not
   on an earlier resolution.
4. Per-domain single-flight plus a global concurrency cap; a bounded work
   queue that **drops** excess triggers rather than growing.
5. Rate limit by target domain (and by observation source where available).
6. Header-triggered resolution is always asynchronous.
7. Private ranges reachable only via an explicit opt-in setting for split-DNS
   deployments (default off) — and that opt-in deliberately does **not** widen
   to link-local: `169.254.169.254` and its IPv6 equivalents are the cloud
   metadata services, the highest-value SSRF target there is, and no mail
   authority has ever legitimately lived there. Reserved space (CGNAT, TEST-NET,
   NAT64, documentation, 240/4) stays refused in both modes.

All seven are implemented in `resolver` and covered by tests that assert the
failure *class*, not just that an error occurred: a metadata address that merely
timed out would pass a weaker test while remaining reachable on a host where it
answers.

### 3.5 Envelope metadata tampering — **F-1, critical, present in today's code**

`mailcore/crypto.Seal`/`Open` pass **`nil` as AEAD additional data**. The GCM
tag therefore covers the ciphertext only: `Space`, `Seq` — and under MKDP1 the
recipient domain, `kid`, `manifest_id` and algorithm identifiers — are
*unauthenticated cleartext*. Spec `04-SECURITY.md §10` requires exactly the
opposite.

Exploitation is not a confidentiality break (the plaintext still needs the
private key), but an on-path attacker can:

- rewrite `kid` so the receiver looks up the wrong retained key → silent
  decryption failure, a targeted per-message DoS that looks like corruption;
- rewrite the recipient domain on a multi-domain server that holds one key,
  so a correctly decrypted message is *attributed to the wrong domain* in
  security metadata and audit logs;
- rewrite `manifest_id` to poison the provenance record of every delivered
  message (log forgery against the exact field the spec wants for audit);
- prepare cross-suite confusion for any future second suite.

Fix: bind a canonical header — version, domain, kid, manifest id, alg, enc,
ephemeral public key — as AEAD associated data. Because this changes the
cryptographic construction it **must** take a new suite identifier
(`02-MKDP1-PROTOCOL.md §11`): the MKDP1 envelope is a new version, and the
legacy nil-AAD suite is retained *decrypt-only* for mail already in flight.

### 3.6 Rollback and stale observations

No public history means nothing to roll back *to*. A stale DNS/header ID is
data, not a command. A cached manifest is usable only while valid. The one
real hazard is an **unstable authority** alternating between valid manifests:
MKDP1 refuses to invent an ordering rule and instead raises a warning — the
honest choice, since any tie-break here would be attacker-controllable.

### 3.7 Downgrade to plaintext vs. denial of service — the tension (F-4)

Two failure modes pull against each other:

- *Downgrade*: known encrypted peer → transient failure → plaintext. Must not
  happen silently.
- *Self-DoS*: an unauthenticated observation arms fail-closed for a domain →
  attacker stops our mail.

Resolution: fail-closed state may be armed **only** by a successful HTTPS
validation or explicit administrator policy — never by DNS or a header. When a
validated peer has no usable manifest, the message **holds in the queue** and
retries (default) or fails per policy, and the operator is notified; it is
never quietly downgraded. Holding is bounded by the queue's normal give-up, so
the failure surfaces as a DSN rather than an infinite hold.

### 3.8 Identifier attacks

Full 32-byte SHA-256, never truncated on the wire, never compared
lexicographically. The `kid` preimage includes domain, alg and enc, which
kills cross-domain and cross-suite substitution. One rule needs enforcement
teeth: **a `kid` mapping must never be overwritten with a different
descriptor** — treat it as a critical integrity error, refuse, and alert
(F-6). Truncation for display is fine; the full value must be inspectable.

### 3.9 Hostile manifest parsing (F-7)

The endpoint is attacker-controlled bytes. Two subtleties beyond the spec text:

- `value`'s decode limits (`MaxParseDepth`, `MaxParseCollectionLen`,
  `MaxParseByteLen`) are **package-level variables**. A library must not
  mutate them — that would silently retune the host application's parser.
  Bounds must instead come from the 16 KiB body cap plus *structural*
  validation (exact key set, exact kinds, exact lengths), which is
  independent of the host's globals.
- `value.Unpack` parses one value and ignores trailing bytes. The mandated
  canonical repack-and-compare catches that for free: repacked bytes cover
  only the value, so any trailing garbage changes the length.

Also note `value` distinguishes `Utf8` (str family) from `Raw` (bin family) as
different kinds — so `pk` supplied as a string, not binary, must be rejected
by kind, not coerced.

### 3.10 Retention arithmetic (F-9)

FR-6's retention floor (max manifest lifetime + max delivery lifetime + skew)
is a *correctness* requirement disguised as configuration: prune sooner and
delayed mail becomes permanently unreadable. Retire, never delete, and make
the floor the enforced default.

### 3.11 New public surface on 443 (F-5)

MKDP1 requires an always-public HTTPS endpoint at `mail.<d>`. The endpoint
itself is about as safe as HTTP gets — unauthenticated GET, static prebuilt
bytes, no query parameters, no per-request serialization — but the *listener*
is the risk: a dedicated public :443 must serve **only**
`/.well-known/mail-key` and 404 everything else. Mailnite already learned this
with the challenge-only ACME server on :80; MKDP1 reuses that exact shape, and
must never mount webmail or the admin console on that listener.

### 3.12 What MKDP1 does not authenticate

Encryption is not sender authentication. Anyone can seal a message to a
published key; SPF/DKIM/DMARC remain the sender-identity layer, and the
envelope AAD binds *metadata*, not authorship. Worth stating plainly so
nobody reads "encrypted" as "authentic".

Forward secrecy is partial: the sender's key is ephemeral, but compromise of
the recipient's long-term private key opens every message sealed to it.
Rotation plus bounded retention is the only mitigation, which is another
reason the retention floor must not become an unbounded archive.

---

## 4. Findings summary

| # | Severity | Finding | Disposition |
|---|---|---|---|
| F-1 | **Critical** | Envelope AEAD uses nil AAD; metadata unauthenticated (spec §10 violation) | FIXED in both: mailkey's MKDP1 suite binds every identifier; **mailcore envelope v2** binds its routing metadata, v1 decrypt-only. The published mathematics page (§2.7) was updated ×8 — it had documented the nil-AAD construction, with a justification that was itself incomplete (the HKDF salt binds the keys, never `space`/`seq`) |
| F-2 | High | Header path currently *installs* keys (`LearnPin`) | Clean break: header becomes observation-only; seq/conflict machinery removed |
| F-3 | High | Header-triggered fetch is a remote SSRF/amplification primitive | Full resolver hardening (§3.4), private targets opt-in |
| F-4 | Medium | Downgrade protection vs. observation-driven self-DoS | Implemented in `peer`: a failed refresh never disturbs a valid manifest, `ResolveForEncryption` falls back to cache and otherwise reports `ErrNoKey` rather than deciding plaintext; fail-closed armed only by HTTPS/admin. The queue-side hold/fail policy is phase 8 |
| F-5 | Medium | New always-public 443 endpoint | Dedicated well-known-only handler; relay/mux sharing like AcmeServer |
| F-6 | Medium | `kid` remap would corrupt lookup silently | Refuse + alert as critical integrity error |
| F-7 | Low | Parser hardening must not touch `value` globals | Structural validation + body cap; repack catches trailing bytes |
| F-8 | Low | Clock skew / lifetime bounds | Enforced in `Validate`, cache headers ≤ `expires_at` |
| F-9 | Low | Retired-key retention floor is a correctness requirement | Enforced default, retire-not-delete |
| F-10 | Info | No CT, no pinned signing key | Documented accepted limitation |
| F-11 | Medium | Domain normalization was not idempotent (a Punycode A-label whose decoded form is invalid normalized once, then failed on its own output) | `Normalize` verifies stability and rejects; found by fuzzing |
| F-12 | Medium | Base64url identifiers had multiple valid spellings (unused trailing bits ignored), so one id could be advertised under different-looking strings | `DecodeID` requires the canonical spelling; found by fuzzing |
| F-13 | Medium | At-rest private-key wrapping (`mailcore/service`) also used nil AAD, so a wrapped blob was anonymous ciphertext: it could be moved between records or generations and would still unwrap | `wrap`/`unwrap` bind (owner, seq) as associated data; clean break, no unbound fallback |
| F-14 | Medium | The blob store (`mailnite/pkg/blob`) used nil AAD, and chunk/object files are plain files OUTSIDE the encrypted key-value store — so a writer without the key could splice one sealed entry over another's location and the read would return the wrong message's content | Entries bind their location (`chunk\|<id>\|<offset>`, `object\|<id>`); the seal moved inside the write lock so the location is known first |
| F-15 | Medium | DKIM signing keys (`mailcore/queue`) are sealed under one host wrap key with a CONSTANT as associated data, while key files are per-domain (`<domain>.key`) — so a sealed file could be copied into another domain's slot and would open there. The server would then sign that domain's mail with the wrong key, and every signature would fail against the DKIM record the domain publishes: silent, total deliverability loss that looks like a DNS problem. Found by the exhaustive AEAD sweep below, not by the MKDP1 work | Sealed files bind their domain (`MAILNITE-SEALED-KEY.v2\|<domain>`); v1 files are refused with an actionable message rather than opened, since their bytes carry no domain at all |

### 4b. The exhaustive AEAD sweep

Every AEAD construction in the three repositories, audited for the two failure
modes that matter: unbound ciphertext (a blob that opens somewhere it does not
belong) and nonce reuse (catastrophic for GCM). Eight sites:

| Site | Associated data | Nonce | Verdict |
| --- | --- | --- | --- |
| `mailkey/envelope` | every header field (suite, domain, kid, manifest id, alg, enc, ephemeral key) | random per message, under a per-message key from a fresh ephemeral ECDH | correct |
| `mailcore/crypto` (legacy envelope v2) | version, alg, key space, generation, ephemeral key | as above | correct |
| `mailcore/service` at-rest key wrap | `(type, owner, seq)` | random, few wraps per long-lived key | correct (F-13) |
| `mailcore/queue` DKIM key seal | **constant** → now `(header, domain)` | random | **F-15**, fixed |
| `mailnite/pkg/keeper` sealed keys | the file's own name | random | correct — one file, so the name IS its location |
| `mailnite/pkg/blob` chunk entries | `chunk\|<id>\|<offset>` | random per entry; 96-bit birthday bound at ~2^48 entries, far beyond mail volumes | correct (F-14) |
| `mailnite/pkg/blob` objects | `object\|<id>` | as above | correct (F-14) |
| `mailnite/pkg/web` Web Push | empty, per RFC 8291 | HKDF-derived from a per-message random salt | correct by specification |

The pattern behind F-1, F-13, F-14 and F-15 is one mistake with four faces:
**ciphertext that does not say where it belongs.** Encryption alone makes a blob
unreadable; it does not make it non-interchangeable. Wherever several blobs are
sealed under the same key and stored in addressable slots — generations of a key,
chunks of a message, one key file per domain — the slot has to be inside the
authenticated data, or an attacker who can move bytes without reading them can
still change what the system believes.

---

## 4a. Findings from fuzzing

Two of the ten findings above were reasoned out from the spec; **F-11 and F-12
were found by the fuzzers**, and both were live defects in code that had passing
hand-written tests. They are worth recording because of what they have in
common: each was a *canonicality* bug, and each would have surfaced as an
interoperability failure rather than an obvious break.

- **F-11 — normalization was not idempotent.** `Normalize("0.\x84")` produced
  `0.xn--zn7c`, and normalizing *that* failed IDNA validation. The domain sits
  inside the `kid` preimage, so two code paths that normalized a different
  number of times would compute different key identifiers for the same key. The
  fix verifies stability and rejects anything without a fixed point — fail
  closed, one canonical spelling.
- **F-12 — identifiers had multiple spellings.** Base64 leaves the final
  character's unused low bits free, so `…001` and `…000` decode to the same 32
  bytes. Beyond the interoperability problem (a string comparison of ids
  reporting a false mismatch), it hands an observer a way to advertise the same
  manifest under a different-looking id and trigger pointless refreshes. The
  decoder now requires the input to re-encode to itself.

**F-13 and F-14 were found by auditing F-1's fix rather than by reasoning about
the spec.**
Having bound the envelope's metadata, the obvious question was where else this
codebase encrypts something whose *name* lives outside the ciphertext — and the
at-rest key wrapping did exactly that. A wrapped private key was anonymous
ciphertext: anyone able to write to the store (a restored backup, a compromised
replica, a buggy migration) could move one domain's wrapped key into another's
record, or a retired generation's into the current slot, and it would unwrap
perfectly. The server would then hold a key belonging to a different identity
while believing it is this one — mail sealed to the real key stops opening, and
the audit trail says something false about which key was used. `wrap`/`unwrap`
now bind (owner, generation), with no unbound fallback: this is an at-rest
format only we produce, so unlike the wire envelope there is no second party to
stay compatible with.

The same question asked once more found F-14 in the blob store. Chunk and object
files are ordinary files on disk — *outside* the encrypted key-value store —
which is what makes them the interesting case: a writer who does not hold the
data key can copy one sealed entry over another's offset, and the read succeeds
and hands back the wrong message's body. They cannot forge the reference that
points at it, because references live in the sealed store, so the location is
precisely the handle they have. Entries now bind their location. (One nil-AAD
site was left alone deliberately: Web Push encryption is RFC 8291, which defines
the associated data as empty — binding anything there would break the standard.)

The property that caught F-11 and F-12 is the same one the protocol depends on:
*anything accepted must round-trip to exactly what was accepted*. That invariant is now
asserted by fuzz targets over the manifest parser, the identifier decoder,
domain normalization and the header parser, and the failing inputs are kept as
regression corpus.

## 5. Verdict

MKDP1 is a well-scoped protocol: it removes the class of attack that motivated
it (forged ordering), refuses to invent tie-breakers an attacker could aim, and
keeps its trust story small enough to state in a paragraph. Its residual risks
are the ones it names honestly — a compromised HTTPS authority and WebPKI
misissuance — plus the two the implementation must earn: SSRF hardening on the
observation-triggered fetch, and authenticated envelope metadata.

F-1 is the one item that must land with the protocol rather than after it:
shipping MKDP1 identifiers inside an envelope that does not authenticate them
would put the protocol's own audit fields under attacker control.
