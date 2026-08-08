# MKDP1 Test Plan

## 1. Canonical serialization tests

Create golden fixtures for:

- a valid manifest;
- the exact canonical MessagePack bytes;
- manifest ID;
- key descriptor bytes;
- `kid`;
- DNS TXT representation;
- `Mail-Key` header representation.

The same logical manifest built with different map insertion orders must produce
identical bytes and identifiers.

Reject:

- noncanonical integer widths;
- unsorted map keys;
- duplicate keys;
- sparse lists;
- floats, decimals, big integers, and extensions;
- overlong public keys;
- deeply nested or oversized input;
- canonical bytes with trailing data.

## 2. Domain tests

Test:

- lowercase normalization;
- trailing-dot removal before protocol use;
- IDNA A-label normalization;
- rejection of URLs, schemes, paths, ports, wildcards, IP literals, and invalid
  labels;
- deterministic DNS name and HTTPS URL.

Expected:

```text
example.com
→ _mailkey.example.com
→ https://mail.example.com/.well-known/mail-key
```

## 3. Identifier tests

Verify:

- sender and receiver calculate identical `kid`;
- changing domain changes `kid`;
- changing algorithm changes `kid`;
- changing encryption mode changes `kid`;
- changing one public-key byte changes `kid`;
- timestamps do not affect `kid`;
- any manifest-field change affects `manifest_id`;
- base64url parsing rejects padding, invalid characters, and wrong lengths;
- a `kid` mapping cannot be overwritten with a different descriptor.

## 4. HTTPS resolver tests

Accept:

- valid certificate for exact discovery host;
- HTTP 200;
- correct media type;
- bounded canonical manifest;
- exact requested domain;
- supported suite and valid timestamps.

Reject:

- expired or untrusted TLS certificate;
- hostname mismatch;
- HTTP redirect;
- non-200 response;
- response over 16 KiB;
- timeout;
- wrong domain in manifest;
- expired manifest;
- excessive lifetime;
- future `issued_at` beyond allowed skew;
- unsupported algorithm;
- `kid` mismatch;
- noncanonical MessagePack.

### Delegated bootstrap

Verify:

- an unpinned header or ordinary DNS observation carrying `a=attacker.example`
  still resolves through `mail.<subject>`;
- a response reachable only through that attacker-selected route cannot
  establish an identity pin or install a manifest;
- the rejected routing claim remains visible as an observation;
- after an identity pin exists, an observed delegated route is eligible, but
  only responses authorized by the established pin can be installed.

## 5. Observation reconciliation tests

### Matching observations

```text
effective HTTPS ID = A
DNS ID = A
header ID = A
```

Both observations become confirmed; no unnecessary refresh is made.

### Stale header

```text
effective HTTPS ID = B
delayed header ID = A
```

The header becomes stale. B remains effective.

### DNS and header disagreement

```text
DNS ID = B
header ID = C
fetched HTTPS ID = D
```

D becomes effective. B and C are recorded as stale/inconsistent observations.
No numeric or timestamp winner is selected.

### Rotation

```text
old fetched ID = A
new fetched ID = B
```

B becomes effective atomically; A becomes historical.

### Authority instability

Repeated valid HTTPS responses alternate A/B/A/B within the warning window.
The system records an authority instability warning without inventing an
ordering rule. A response with the same `issued_at` and a different
`manifest_id` does not replace the effective manifest; a usable cached manifest
continues to serve encryption, otherwise the sender holds.

Also verify:

- the signer is authorized against the established pin before replay fields are
  evaluated;
- copying a current `issued_at` cannot authorize a missing or different signer;
- a verified identity rotation starts a new replay watermark for the successor
  identity rather than inheriting the predecessor's timestamp;
- a successor-only revocation whose `old_fp` names the current pin and whose
  `new_pk` signs the statement is rejected without moving the pin;
- a terminal revocation requires the current old key;
- a revocation that introduces a successor requires old-key authorization and
  new-key proof of possession.

## 6. Peer lifecycle tests

Verify:

- DNS creates one discovered Peer;
- header for the same domain attaches to that Peer;
- manual Add Peer does not create a duplicate;
- successful resolution transitions to active;
- refresh failure preserves an unexpired manifest;
- expired manifest plus failed refresh transitions to expired/unavailable;
- require-encryption prevents plaintext fallback;
- Forget Peer removes cache but permits later rediscovery;
- disabled policy prevents automatic resolution.

## 7. Queue and rotation tests

Scenario:

1. Sender resolves key A and encrypts a message with `kid A`.
2. Receiver rotates and publishes key B.
3. Sender delivers the queued A message after rotation.
4. Receiver resolves `kid A` to the retained private key and decrypts it.
5. New sender messages use `kid B`.

Also verify:

- delivery retries never perform discovery;
- queued storage contains only encrypted envelope data for protected delivery;
- envelope carries and authenticates `kid` and `manifest_id`;
- modifying domain, `kid`, `manifest_id`, suite, or encapsulation metadata causes
  authentication failure.

## 8. Header security tests

Verify:

- user-supplied outbound `Mail-Key` is stripped;
- server-generated header uses `d=example.com`;
- arbitrary host, path, port, or IP is rejected;
- malformed and unknown-version headers are ignored safely;
- header storms are rate-limited and per-domain requests coalesce;
- inbound delivery is not blocked by discovery;
- private/link-local discovery targets are rejected by default.

## 9. Fuzzing

Fuzz:

- `value` manifest parser;
- DNS parameter parser;
- email header parser;
- domain normalization;
- base64url identifiers;
- envelope metadata parser;
- canonical decode/repack comparison.

Properties:

- no panic;
- bounded memory and CPU;
- accepted input always repacks to identical bytes;
- accepted manifest always has a recomputable matching `kid`;
- accepted domain always produces the deterministic allowed URL.

## 10. Interoperability release gate

Before tagging MKDP1:

- Mailnite server and `github.com/mailnite/mailkey` pass identical manifest
  vectors;
- at least two independent processes generate the same bytes and IDs;
- receiver key generation and sender calculation agree on `kid`;
- exact existing envelope crypto vectors are published and verified;
- upgrade tests prove old `kid` mappings remain decryptable;
- Peers UI behavior matches the documented source and conflict semantics.
