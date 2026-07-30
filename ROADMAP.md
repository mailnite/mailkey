# Implementation roadmap

Status of the MKDP1 reference implementation and its Mailnite integration.
Phase 1 is done; the rest is planned in the order dependencies allow.

## Phase 1 — protocol core ✅

- `mailkey` — protocol types and the DI-facing interfaces (`Resolver`, `Store`,
  `Service`, `PrivateKeyLookup`, `Publisher`).
- `mailkey/manifest` — canonical pack/parse, `kid`, `manifest_id`, validation
  limits, golden vectors.
- `mailkey/discovery` — domain normalization (the SSRF boundary), derived TXT
  name and authority URL, DNS/header parse and format.
- `mailkey/envelope` — the `mkdp1-x25519-hkdf-sha256-aes256gcm` suite with all
  identifiers bound as AEAD associated data (security review F-1), canonical
  wire format.
- `SECURITY-REVIEW.md` — attack analysis and findings F-1…F-10.

## Phase 2 — hardened resolver ✅

`mailkey/resolver`: the only code that installs a key, and the only code a
remote attacker can trigger. Everything in the security review §3.4 lands here:

- URL derived from the domain; HTTPS and port 443 only; `GET`; no redirects; no
  proxy authentication.
- Custom `DialContext` validating **every** resolved address at connection time
  — loopback, private, link-local, unique-local, CGNAT, multicast, unspecified
  and reserved ranges refused. This is the DNS-rebinding defense, so it must
  check the address actually dialed, not an earlier resolution.
- Connection/header/body timeouts, 16 KiB body cap enforced before allocation,
  status 200 required, media type checked.
- Canonical parse plus `manifest.Validate`, with the requested domain pinned.
- Per-domain single-flight and a global concurrency cap; a bounded trigger queue
  that drops rather than grows.
- ONE injection seam (`LookupFunc`, name resolution) instead of an injectable
  HTTP client: a substitution cannot weaken anything, because the address policy
  runs on whatever it returns and TLS still validates the derived hostname. The
  port escape needed by tests and split-DNS deployments is honoured only
  together with the private-targets opt-in, so a default configuration can never
  be pointed at another port.
- Failure classification (`mailkey.FailureClass`): network, TLS, absent, http,
  protocol, policy. A 404 is a definitive "this domain does not speak MKDP1",
  not an outage; a 200 carrying an invalid object is an alarm. Callers act on
  the class, never on error text.
- Tests: a real TLS authority with its own CA (hostname mismatch, untrusted
  issuer and expired certificate all asserted by class), the full address-policy
  table including the mapped-IPv4 bypass and cloud metadata, DNS rebinding
  across two connections, redirect refusal, single-flight (20 callers → 1
  request), timeouts, body caps before and after read, cache-lifetime bounding,
  and fuzz targets over every parser.

## Phase 3 — Peer store and service ✅

`mailkey/peer`: the state machine of `03-PEERS-AND-RESOLUTION.md`.

- `peer/state.go` — the transitions as PURE FUNCTIONS over a `*mailkey.Peer`
  (`Install`, `Observe`, `Reconcile`, `Fail`, `Usable`, `NeedsRefresh`,
  `Forget`), so every Store backend shares one implementation of the semantics
  and supplies only persistence and atomicity.
- Observation reconciliation: confirmed / stale / inconsistent against the
  effective manifest id, with no winner-selection between untrusted sources.
  Observations coalesce per source, so a mail flood cannot grow a record.
- Atomic `InstallManifest` (persist → demote previous → set effective →
  reconcile → update status), with history bounded so a flapping authority
  cannot grow storage.
- Authority-instability detection: A → B → A inside an hour is flagged, and the
  latest fetch is still what is effective — no ordering rule invented.
- Downgrade protection in code: `Fail` never disturbs a still-valid manifest,
  and `ResolveForEncryption` falls back to a usable cached manifest when a due
  refresh fails. It returns `ErrNoKey`/the failure rather than ever deciding to
  send plaintext — that decision belongs to the caller's policy.
- Bounded async discovery: header and DNS triggers enqueue onto a fixed-size
  channel drained by N workers, coalesced per domain, and **dropped** when full
  (a lost hint costs nothing; the next send resolves synchronously). Background
  work gets its own context, never the inbound message's.
- `peer/memstore.go` — the reference `mailkey.Store`: returns deep copies so a
  caller cannot mutate stored state, refuses a result for another domain, and
  keeps an administrative policy across `Forget` (a decision about the domain,
  not a cache entry).
- Cache honesty: serving from cache re-parses the stored canonical bytes, so a
  record that no longer validates is refused rather than used.
- 15 tests covering all of the above, including the central rule proven from
  the outside (observations never install a key) and the bounded-queue storm.

## Phase 4 — glue components ✅

`mailkey/component`: two thin beans for dependency-injection applications.

- `ResolverBean` builds the hardened resolver from properties (`mkdp.*`,
  documented in the package comment), warns loudly when
  `mkdp.security.allow-private-targets` widens the anti-SSRF policy, and reports
  `ErrDisabled` rather than making requests when MKDP1 is switched off.
- `ServiceBean` builds the peer service over an injected `mailkey.Resolver` and
  the host's `mailkey.Store`. Both dependencies are INTERFACES, so a host
  substitutes its own storage or resolver without touching protocol behavior;
  a missing store falls back to the in-memory one with a warning rather than
  failing silently. `PostConstruct` is re-entrant (an in-place restart reuses
  bean instances, so the previous worker set is stopped first) and `Destroy` is
  idempotent.
- Interface classes (`mailkey.ResolverClass`, `StoreClass`, `ServiceClass`,
  `PrivateKeyLookupClass`, `PublisherClass`) so a container resolves the
  protocol by what it does, never by an implementation type.
- The core packages stay free of the DI dependency: `mailkey`, `manifest`,
  `discovery`, `envelope`, `resolver` and `peer` import only the standard
  library, `value` and `xerrors`.
- Tests build a real glue container and drive the protocol through the injected
  interfaces, including the disabled switch, the missing-store fallback, the
  restart/destroy lifecycle and property plumbing.

## Phase 5 — mailcore changes ✅ (mailnite wiring included)

Done in mailcore:

- `api.KeyResolver` reshaped: `ResolveKey(ctx, address) (mailkey.Result, bool,
  error)`. The queue asks for a validated *manifest result*, not a bare public
  key, so the envelope's identifiers cannot drift from the discovery that
  authorized them. mailcore now imports mailkey — the alternative was a second
  copy of the envelope construction, which is the drift bug twice over.
- `crypto/mkdp.go`: `SealMKDP1` / `OpenMKDP1` / `IsMKDP1` wrap a mailkey
  envelope in the same outer message shape. The legacy `Seal`/`Open` stay
  DECRYPT-ONLY for mail already in a queue or mailbox; the `Mail-Key-Suite`
  header says which format a message carries, so the parser is chosen from the
  message rather than guessed.
- The `seq`-ordered resolver chain is DELETED (`crypto/resolver.go`: DNSResolver,
  ChainResolver, StaticResolver and the per-domain seq high-water). Security
  review F-2 — leaving the old ordering beside MKDP1 would reopen the
  frozen-rotation bug.
- Per-domain keys are now visible in the tests: a second mailbox at a published
  domain is covered by the same manifest (the old test asserted the opposite,
  because the retired scheme published per user).

Done in mailnite (the wiring the mailcore change requires):

- `pkg/server/mailkey_store.go` — the durable `mailkey.Store` (region
  `"mailkey"`), persistence only: every transition comes from `mailkey/peer`'s
  pure functions, so it cannot drift from the library's reference store.
  Atomicity is a per-domain lock plus a single-key write.
- `pkg/server/mailkey_component.go` — resolver, store and service built ONCE and
  shared by the queue and the admin surface (two builders would mean two caches
  disagreeing about the same domains). Re-entrant across the in-place restart.
- `KeyResolverFactory` now returns the MKDP1 adapter; "outbound encryption off"
  is a resolver that finds nothing.
- The `Mailnite-Key` key-installing path is DELETED (`pubkey_header.go`,
  `learnPeerKey`, the stamping call) — F-2's other half. MKDP1's `Mail-Key`
  header carries a manifest id, which needs the publisher (phase 6).
- The pin book is DELETED (`peer_pins.go`: seq-monotonic `LearnPin`, the conflict
  ledger, `PinEntry`/`ConflictEntry`). `admin.peers.*` is now
  `list/add/refresh/forget/policy` over the peer book — Add takes a DOMAIN and
  nothing else.
- The Peers page and its i18n (×8) follow: no key field, no sequence number, no
  conflict card. The `peers.conflict` alert is replaced by `peers.unstable`
  (authority instability), emitted from the one place that can detect it.
- `mailnite key lookup` now probes MKDP1 and prints the manifest id, kid and
  validity.

## Phase 6 — Mailnite receiver and publisher ✅

- **kid lookup is DERIVED, not stored** (`mailcore/service/key_mkdp.go`). A kid
  is SHA-256 over (domain, alg, enc, public key), so the lookup recomputes it
  from the stored key material and compares. That is stronger than the mapping
  F-6 warned about: there is no stored association to corrupt, so a kid can
  never name a key it was not derived from, and the F-6 alert has nothing to
  fire on. `KeyByKid` is on `api.KeyService`; `FindPrivateKey` satisfies
  `mailkey.PrivateKeyLookup`.
- The trial walk is gone for MKDP1 mail: `DecryptFor` routes an MKDP1 envelope
  to exactly one candidate generation. The walk survives ONLY for legacy
  envelopes, which name a generation number rather than a key — dropping it
  would strand mail already in mailboxes and queues.
- The recipient domain selects the keyring from the LOCAL mailbox, and the
  envelope's claimed domain must match it. An envelope for another domain is
  left sealed rather than opened with a key it does not belong to.
- **Retention floor enforced in code** (F-9): manifest lifetime + delivery
  lifetime + margin (7 + 10 + 14 days). `RetTimestamp` records when a
  generation retired, because retention is measured from retirement, not
  creation — a key created long ago but retired a minute ago may still be
  needed. An operator may LENGTHEN the window and cannot shorten it: a shorter
  window is not a trade-off, it is data loss. A generation with no retirement
  timestamp is kept rather than guessed about.
- **Publisher** (`mailnite/pkg/server/mailkey_publisher.go`): per hosted domain,
  the canonical manifest bytes and their id, built once and served verbatim —
  the id is the hash of exactly those bytes, so re-serializing per request could
  serve bytes whose hash differs from the id already advertised. It refuses to
  publish for a domain this server does not host, for a domain with no key, and
  for a key whose private half is not resolvable by the kid about to be
  published (the state that would silently break every message sealed to it).
- Tests: publish → validate as a peer would → seal → open by kid, all in one
  process (the only way to prove the two halves agree); rotation with a delayed
  message still opening; the derived-lookup properties (a kid does not resolve
  under another domain's keyring, a fabricated kid resolves to nothing); the
  retention floor.

Remaining from this phase, moved to phase 7 where they belong: the `_mailkey`
DNS record and the `Mail-Key` header both advertise the published manifest id,
so they land with the endpoint that serves it.

## Phase 7 — the public 443 endpoint ✅

A dedicated well-known server, modelled on Mailnite's challenge-only ACME server
on :80 (`pkg/server/acme_server.go`), because the port-sharing problem is
identical. `mailKeyVia` decides once, the same shape as `acmeChallengeVia`, so
the relay port set, the status table and the server cannot disagree:

- **any local webmail port is bound** → `web.MailKeyWellKnown` is an ordinary
  handler bean, so servion serves it on every web server in the scope: the HTTP
  mux, the HTTPS mux and the loopback console alike. Sharing 443 needs no code.
- **none is** (the web pair rides the relay while mail does not, or both webmail
  servers are off) → `server.MailKeyServer` takes a dedicated listener on public
  443 and serves `/.well-known/mail-key` only, 404 for everything else (F-5),
  terminating TLS under the mail server's own certificate.
- **mail rides the relay** → the authority is on the VDS, so a local port is no
  help: either webmail's relayed HTTPS server carries the endpoint, or the
  dedicated server takes the relay's public 443.
- The claimants are mutually exclusive by construction, and tests assert both
  that the relay set never contains two of them and that a dedicated listener is
  never chosen while a local webmail port is bound.

**Being on both local ports is the point, not a side effect.** Which one fronts
public 443 is the operator's routing decision and the process cannot see it: a
datacenter host maps 443 → 8443 and it stays TLS, while a Kubernetes ingress
TERMINATES TLS and maps 443 → the pod's **8080** in plaintext, leaving 8443
possibly serving nothing. So `mailKeyVia` asks only whether ANY webmail server
binds locally, and TLS is required only for a listener we terminate ourselves —
an earlier version gated the whole decision on `tls.enabled`, which reported "no
endpoint" for exactly the pod deployment where the mux was in fact answering.
Inside Kubernetes `webmailHTTPEnabled` is unconditionally true, so a pod always
shares the mux and never binds a port nothing routes to. The status row names
every answering port instead of calling one of them "the" 443.

`mailkey/wellknown` holds the handler, so any MKDP1 server gets the caching and
method rules right: `ETag` = the manifest id (a strong validator that cannot lie,
since the id is the hash of the bytes), `max-age` = min(remaining validity, 1
hour), conditional requests, `no-store` on a miss, `GET`/`HEAD` only.
`discovery.DomainCandidatesOf` maps a Host header back to a domain — the inverse
of `AuthorityHost`, in the library because doing it by string surgery is how
host-header bugs happen.

Also landed here, since both advertise the id this endpoint serves:

- the `_mailkey.<domain>` TXT record replaces `_mailpubkey` in the operator
  checklist, and `mailcore/crypto/dns.go` is deleted;
- the `Mail-Key` header replaces `Mailnite-Key` on outbound mail (and in DKIM's
  signed set), carrying a manifest id and no key;
- inbound `Mail-Key` headers become observations on mail that survives filing.

Two defects fixed on the way, neither visible to unit tests:

- **publication lagged rotation.** `Invalidate` had no callers, so a rotated key
  would not be published until the old manifest neared expiry — days of
  advertising the key the operator had just replaced. `CurrentManifest` now
  re-derives the current key's `kid` per request and rebuilds when it differs, so
  correctness no longer depends on anyone remembering to invalidate.
- **onboarding never minted the primary domain's encryption key.** It was created
  only by `AddLocalDomain` or a primary-domain change, so a fresh install
  published nothing — and told every correspondent to send cleartext — until an
  administrator happened to open the DNS page. `Bootstrap` now mints it, as
  adding a domain always did.

## Phase 8 — key lifecycle UI, Peers UI and outbound policy ✅

### Our own keys: a per-domain section on Administration → Domains

The receiving half had a lifecycle nothing could see: a key is issued, published
for a bounded validity, replaced by a rotation, retained while delayed mail may
still name it, then pruned. `DomainKeysCard` shows it per hosted domain — current
`kid` and since when, whether the endpoint is actually publishing (with the
manifest id and how long senders may cache it), the retired generations with
their retirement and prunable dates, and the retention window.

Two states are surfaced as problems rather than merely rendered, because both are
silent losses rather than errors: a hosted domain with **no key** (every
correspondent then sends to it in cleartext) and a key that exists while
publishing is switched off. They are reported separately because they have the
same symptom and different fixes.

Actions: **Issue** for a domain that has none, and **Rotate** behind a
confirmation that states the consequence — senders keep using the previous key
until their cached manifest expires, so both generations must stay openable.
Retention below the floor is **refused, not clamped**: a clamped value reads as
accepted, and an operator would then trust a window that is not in force.

`api.KeyService` gained `ServerKeyStatus`, which returns public halves only — an
administration surface must be able to ask "what state are these keys in" without
being able to extract anything. `FloorDays` reports the CONSTANT minimum rather
than the effective window, so a value the operator chose never looks like a limit
the software imposes.

Deliberately not part of onboarding: the wizard issues the primary domain's key
and moves on.

### Peers

The page already carried the Peer model from phase 5 (state, `kid`, expiry,
observed sources, policy including require/automatic/disabled, last error, the
instability marker, Add/Refresh/Forget). Phase 8 added the two fields it was
missing — the effective **manifest id** and **last verified** time — as sub-lines
under the identifiers they qualify. The conflict card is gone with the ordering
rules it existed to arbitrate; authority instability took its place.

### Outbound policy: hold, never leak, never bounce (F-4)

`PolicyRequire` now has teeth. `peer.Service.ResolveForEncryption` applies the
policy to a discovery failure and reports `mailkey.ErrEncryptionRequired` —
wrapping the cause, so an operator still sees *why* discovery failed — and
mailnite's resolver adapter passes that one error through instead of translating
it into "no key", which would mean cleartext.

The queue turns it into a **temporary refusal of the whole submission**, before
anything is stored:

- Nothing is sent in the clear, which is the point.
- Nothing is bounced. The refusal is `api.ErrEncryptionRequired`, and the SMTP
  session answers **451** — a permanent rejection would let anyone who can make
  an authority unreachable destroy mail instead of merely delaying it, which is
  the self-DoS half of F-4.
- Nothing is partially enqueued. Discovery moved into a pre-pass over all
  recipients, so a mixed submission is refused atomically; storing the reachable
  recipients and failing would make the sender's retry deliver those twice.

Discovery stays at accept time rather than delivery time, and that is now stated
where it is enforced: the queue seals and THEN DKIM-signs, so sealing later would
invalidate a signature already computed over the stored bytes.

## Phase 9 — interoperability gate ✅

The release checklist of `06-TEST-PLAN.md` §10, written up in `INTEROP.md`.

**Published vectors.** `testdata/vectors.json` is the artifact a third-party
implementation is checked against: the manifest inputs, the canonical bytes, both
identifiers, both advertisement forms, the transport constants, and an envelope
decrypt vector (private key, wire bytes, expected plaintext). It states its own
inputs, so nothing has to be taken on trust — and `TestPublishedManifestVectors`
/ `TestPublishedEnvelopeVector` recompute every value on each run, because
published vectors that drift from the code are worse than none.

The envelope vector is a DECRYPT vector by necessity: every envelope carries a
fresh ephemeral key and nonce, so no implementation can reproduce another's
bytes. Being able to OPEN them is the property that matters, and it transitively
checks the suite — the header fields are authenticated as associated data.

**Two independent implementations.** `mailnite/e2e/mkdp1-independent.mjs` is a
hand-written, dependency-free JavaScript implementation of the canonical
MessagePack codec and both identifiers, written from the protocol description and
sharing no code with the server. Reaching for a MessagePack library would have
tested that library's agreement with Go's, not the protocol's clarity. It runs in
the e2e ladder against a live authority — on a runtime-generated key, and again
after a rotation — and must agree on the bytes, the manifest id and the `kid`.

**Fuzzing** covers all seven parsers the plan lists (the two that were missing,
`FuzzParseDNS` and the envelope's `FuzzUnmarshal`, were added here), plus
`TestDecodeBombIsBounded` for the "bounded memory and CPU" property — tiny inputs
claiming four-billion-entry maps.

That fuzzing found **F-16** immediately: the envelope parser accepted
non-canonical encodings, so two byte strings decoded to one envelope while the
AAD — computed from the parsed fields — authenticated both. It now repacks and
requires byte-identical input, exactly as the manifest parser always has.

**Gaps closed** that the plan named and nothing covered: one domain is one Peer
across all three observation sources (§6), delivery retries never perform
discovery (§7 — structural, since the queue seals then signs), and inbound
delivery is never blocked by discovery (§8, including a broken observation
backend and malformed headers).

**The public documentation** described a protocol this software no longer runs.
The Directory page was rewritten in all 8 languages — the record now carries a
manifest id and is optional, the authority is HTTPS, the three-field grammar
replaces six, rotation has no sequence number and the section says why the old
ordering rule was the bug, and the threat model improved rather than shrank (a
forged record can now only cause a fetch). The interactive composer builds a
`_mailkey` record and states plainly that a real id cannot be composed by hand.
The mathematics page, the home page's send path and the deploy page's zone file
followed.

