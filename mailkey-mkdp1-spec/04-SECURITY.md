# MKDP1 Security Model

## 1. Trust boundary

MKDP1 trusts:

- the operating system's WebPKI trust store;
- correct TLS hostname validation for `mail.<domain>`;
- the integrity of Mailnite's local Peer cache and configuration;
- the receiver's private-key/HSM controls;
- the defined Mailnite envelope cryptography.

MKDP1 does not create a new certificate authority or transparency system.

## 2. Security provided

MKDP1 provides:

- authenticated discovery of the current public key through HTTPS;
- protection from arbitrary public sequence-number attacks;
- deterministic, collision-resistant key lookup identifiers;
- binding between an encrypted envelope and the manifest used to create it;
- encryption before queue persistence and SMTP relay handling;
- bounded key rotation without trial-decrypting every private key;
- explicit source semantics so DNS and headers cannot install keys.

## 3. Security not provided

MKDP1 does not protect against:

- compromise of the destination domain's HTTPS service;
- WebPKI CA misissuance accepted by the sender;
- compromise of the receiver private key or HSM authorization path;
- malicious behavior by a fully compromised Mailnite receiver;
- account-to-account attacks after server-side decryption;
- traffic analysis, message size disclosure, or SMTP metadata disclosure;
- local plaintext exposure during processing after successful decryption.

## 4. Discovery-source attacks

### Forged DNS record

Effect:

- may trigger a bounded HTTPS request;
- may provide an incorrect observed manifest ID.

It cannot install a key because the key is fetched and authenticated through
HTTPS.

Mitigations:

- DNS response-size and parsing limits;
- resolution coalescing;
- caching and rate limits;
- never activating require-encryption solely from DNS.

### Forged `Mail-Key` header

Effect:

- may trigger a bounded asynchronous HTTPS request;
- may create a false or stale observation.

It cannot install a key.

Mitigations:

- validate and normalize `d`;
- derive the host rather than accepting one;
- block IP literals and private/link-local resolution targets;
- rate-limit by source and target domain;
- do not block inbound delivery;
- strip locally submitted `Mail-Key` fields before adding Mailnite's own field.

### Manual operator error

The normal form accepts only a domain. TLS and manifest validation remain
mandatory, preventing a copied public key or sequence number from bypassing the
protocol.

## 5. SSRF protections

Because headers may trigger discovery, the resolver MUST:

- accept only normalized public DNS domains;
- construct the URL internally;
- use only HTTPS port 443;
- reject IP-literal domains;
- reject redirects;
- reject resolved loopback, private, link-local, multicast, and otherwise
  prohibited destination addresses according to deployment policy;
- consider DNS rebinding by validating addresses for each connection;
- apply per-domain and global concurrency limits.

Private Mailnite deployments needing split DNS must opt into private destination
ranges explicitly.

## 6. Rollback and stale data

MKDP1 intentionally has no public history or sequence number.

- A sender may use a cached manifest only while it remains valid.
- An observed older DNS/header ID is stale information, not a rollback command.
- A new successful HTTPS response is authoritative.
- `issued_at` is not a winner-selection mechanism.
- The receiver retains old private keys because messages encrypted while an old
  manifest was valid may be delivered later.

Without a separate pinned application signing key, MKDP1 cannot distinguish an
authorized HTTPS rotation from malicious behavior by a compromised HTTPS
authority. This is an accepted MKDP1 limitation.

## 7. Downgrade protection

The dangerous failure mode is:

```text
known encrypted peer
→ temporary DNS/HTTPS failure
→ automatic plaintext delivery
```

Mailnite MUST avoid this.

Once an HTTPS manifest has been validated:

- use it until its expiration;
- refresh before expiration;
- when no valid manifest is available, queue or fail according to local policy;
- require an explicit administrator action to disable MKDP behavior.

A header or DNS record alone must not create a permanent fail-closed policy,
because unauthenticated observations could otherwise be used for denial of
service.

## 8. Identifier security

`kid` and `manifest_id` use full SHA-256 digests.

- Never choose a key based on lexicographic or numeric comparison of IDs.
- Never truncate IDs on the wire.
- Never overwrite a `kid` mapping with a different key descriptor.
- UI may abbreviate IDs visually but must provide the full value on inspection
  and copy.

The domain and algorithm identifiers are included in the `kid` preimage to
prevent cross-domain and cross-suite confusion.

## 9. Manifest parser safety

The public endpoint is attacker-controlled input. The library must:

- bound body size before allocation;
- enforce short timeouts;
- limit nesting and collection sizes below the generic `value` defaults;
- reject forbidden value types;
- reject noncanonical bytes;
- reject unknown algorithms;
- validate all raw key lengths;
- fuzz parsing and canonical validation.

## 10. Envelope requirements

The encryption implementation must authenticate:

- recipient domain;
- `kid`;
- `manifest_id`;
- algorithm identifiers;
- encapsulation metadata.

Otherwise an attacker could alter lookup or algorithm metadata independently of
the ciphertext.

The external `mailkey` repository must include exact envelope test vectors.
Canonical manifest discovery alone cannot compensate for an ambiguous or custom
cryptographic construction.

## 11. Logging and privacy

Security logs should contain:

- domain;
- manifest ID;
- `kid`;
- observation source;
- validation result;
- error class and timestamp.

Logs should not contain:

- private keys;
- shared secrets;
- decrypted email bodies;
- entire messages merely to explain a header observation.

