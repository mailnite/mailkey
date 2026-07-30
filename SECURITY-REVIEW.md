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
   deployments (default off).

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
| F-1 | **Critical** | Envelope AEAD uses nil AAD; metadata unauthenticated (spec §10 violation) | New MKDP1 envelope suite with AAD binding; legacy suite decrypt-only |
| F-2 | High | Header path currently *installs* keys (`LearnPin`) | Clean break: header becomes observation-only; seq/conflict machinery removed |
| F-3 | High | Header-triggered fetch is a remote SSRF/amplification primitive | Full resolver hardening (§3.4), private targets opt-in |
| F-4 | Medium | Downgrade protection vs. observation-driven self-DoS | Fail-closed armed only by HTTPS/admin; hold-and-retry default |
| F-5 | Medium | New always-public 443 endpoint | Dedicated well-known-only handler; relay/mux sharing like AcmeServer |
| F-6 | Medium | `kid` remap would corrupt lookup silently | Refuse + alert as critical integrity error |
| F-7 | Low | Parser hardening must not touch `value` globals | Structural validation + body cap; repack catches trailing bytes |
| F-8 | Low | Clock skew / lifetime bounds | Enforced in `Validate`, cache headers ≤ `expires_at` |
| F-9 | Low | Retired-key retention floor is a correctness requirement | Enforced default, retire-not-delete |
| F-10 | Info | No CT, no pinned signing key | Documented accepted limitation |

---

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
