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

## Phase 2 — hardened resolver

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
- Injected `net.Resolver` and `http.Client` seams for tests — a substitution
  must not be able to weaken the address or redirect policy.

## Phase 3 — Peer store and service

`mailkey/peer`: the state machine of `03-PEERS-AND-RESOLUTION.md`.

- Observation reconciliation: confirmed / stale / inconsistent against the
  effective manifest id, with no winner-selection between untrusted sources.
- Atomic `InstallManifest` (persist → demote previous → set effective →
  reconcile → update status).
- Authority-instability detection (A/B/A/B within a window → warning, never an
  ordering rule).
- An in-memory `Store` for tests and small deployments; Mailnite supplies the
  badger-backed one.

## Phase 4 — glue components

`mailkey/component`: thin beans for dependency-injection applications —
`BeanName`, `PostConstruct`, `inject:""` tags — wrapping the phase 2 and 3
implementations. The core packages stay free of the DI dependency so the library
is usable without it; component apps get ready-made wiring.

## Phase 5 — mailcore changes

- Retire the `seq`-ordered `_mailpubkey` resolver chain and the `Mailnite-Key`
  key-installing path (security review F-2) — a clean break, no dual behavior:
  keeping the old ordering alongside MKDP1 would reopen the frozen-rotation bug.
- `api.KeyResolver` reshaped around `kid`: the queue asks for a *manifest
  result*, not a bare public key, so the envelope's identifiers cannot drift
  from the discovery that authorized them.
- Keep the legacy envelope decode-only for mail already in flight.

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
