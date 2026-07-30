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
  DECRYPT-ONLY for mail already in a queue or mailbox; the `X-Mailnite-Alg`
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

## Phase 6 — Mailnite receiver and publisher

- Per-domain key generation computing `kid` at generation time; `kid → key`
  mapping that **refuses** rebinding (F-6) and alerts through the notification
  fabric.
- Retired-key retention with the enforced floor: max manifest lifetime + max
  delivery lifetime + skew (F-9). Retire, never delete.
- Prebuilt canonical manifest bytes published atomically, so no client can see
  a manifest naming a key the receiver cannot yet open.

## Phase 7 — the public 443 endpoint

A dedicated well-known server, modelled on Mailnite's challenge-only ACME
server on :80 (`pkg/server/acme_server.go`), because the port-sharing problem
is identical:

- `mail.{domain}` must answer on public **443** independently of the local or
  Kubernetes webmail port (8443).
- When webmail's HTTPS server owns 443, mount the handler on its mux.
- When mail rides the relay and webmail does not, take a **dedicated relay
  listener on public 443 that serves only `/.well-known/mail-key`** and 404s
  everything else — never webmail, never the admin console (F-5).
- Static prebuilt bytes, `ETag` from the manifest id, `Cache-Control` bounded by
  `expires_at`.

## Phase 8 — Peers UI and outbound policy

- The Administration → Peers page reshaped to the Peer model: state, effective
  manifest id, `kid`, expiry, last verification, observed sources, policy, last
  error; actions Add / Refresh / Require encryption / Return to automatic /
  Forget.
- Outbound policy: hold-and-retry rather than silent plaintext for a validated
  peer with no usable manifest (F-4), fail-closed armed only by HTTPS validation
  or explicit administrator action.
- The conflict card retires with the ordering rules it existed to arbitrate;
  authority instability takes its place.

## Phase 9 — interoperability gate

The release checklist of `06-TEST-PLAN.md`: two independent processes producing
identical bytes and identifiers, envelope vectors published, rotation and
delayed-delivery tests, header-storm and SSRF tests, fuzzing of every parser.
