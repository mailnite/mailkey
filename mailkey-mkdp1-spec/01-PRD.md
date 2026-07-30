# Product Requirements Document: MKDP1 and Mailnite Peers

Status: Draft 0.1  
Target: Mailnite and `github.com/mailnite/mailkey`

## 1. Problem

Mailnite encrypts an outbound message before persisting it in the delivery
queue. The encrypted message may remain queued, be retried, or be delivered
through an SMTP relay. Therefore, destination-key discovery must occur before
queue persistence and cannot depend on a later SMTP connection.

The existing public `seq` value began as a private-key lookup identifier but
also became an ordering mechanism where the maximum sequence won. That allows a
malicious observation with an arbitrarily large sequence number to block future
legitimate rotations.

The existing Peers page accepts information observed through DNS, email headers,
and manual entry. Without a clear trust and resolution model, those observations
can appear to be competing authorities.

## 2. Product objective

Create a small protocol and reusable Go library that:

1. Resolves the current public encryption manifest for an email domain before
   outbound queue persistence.
2. Uses normal HTTPS/WebPKI authentication at a deterministic hostname.
3. Replaces public sequence numbers with deterministic key identifiers.
4. Integrates DNS, email-header, and manual discovery into one predictable Peer
   model.
5. Retains old receiver private keys so delayed encrypted messages remain
   decryptable.
6. Fails safely without silently downgrading a known MKDP1 peer to plaintext.

## 3. Non-goals

MKDP1 will not implement:

- account-to-account encryption;
- SMTP or post-STARTTLS key discovery;
- Merkle trees or append-only public logs;
- witnesses, gossip, or blockchain consensus;
- public key chains or public sequence numbers;
- application signatures on the manifest;
- arbitrary discovery hostnames;
- discovery through MX targets;
- manual raw-key entry as a normal automatic MKDP1 source;
- a replacement for TLS between HTTP or SMTP endpoints.

## 4. Users

### Mail administrator

Uses the Peers page to:

- see discovered MKDP1-capable domains;
- add a domain manually;
- refresh a peer;
- inspect the effective manifest and observation history;
- require encrypted delivery for a domain;
- forget a peer with an explicit downgrade warning.

### Mailnite outbound pipeline

Needs a validated encryption key before producing and storing the destination
envelope.

### Mailnite inbound pipeline

Uses `kid` for constant-time lookup of the appropriate historical private key
or HSM handle.

### Third-party Go integrator

Uses `github.com/mailnite/mailkey` to parse discovery records, resolve and cache
manifests, calculate identifiers, and validate protocol objects.

## 5. Core product decisions

### 5.1 Peer versus manifest

A Peer is not itself a manifest. A Peer is the stable domain-level record:

```text
Peer(example.com)
  effective manifest → manifest ID A
  historical manifests → IDs B, C
  discovery observations → DNS, header, manual
  administrative policy → automatic or require-encryption
```

Manifests are immutable cached objects. A newly fetched valid manifest becomes
effective atomically. The preceding manifest may be retained for diagnostics
and delayed-message support.

### 5.2 Discovery sources

DNS, email headers, and manual addition have different operational origins but
do not create different cryptographic trust levels:

| Source | What it does | Can install a key? |
|---|---|---:|
| DNS TXT | Advertises MKDP1 and an observed manifest ID | No |
| `Mail-Key` header | Advertises MKDP1 and an observed manifest ID | No |
| Manual Add Peer | Requests immediate resolution for a domain | No |
| Deterministic HTTPS | Returns the validated effective manifest | Yes |

The word “manual” describes who initiated resolution, not how the key is
authenticated.

### 5.3 Standard authority

For `example.com`, the only automatic MKDP1 authority is:

```text
https://mail.example.com/.well-known/mail-key
```

The TLS certificate must be valid for `mail.example.com`. Redirects are not
followed in MKDP1.

### 5.4 No public ordering

There is no sequence number and no “greatest value wins” rule. The current
successful HTTPS response is authoritative. `issued_at` is checked for sanity
and diagnostics but is never used to choose a winner among untrusted objects.

## 6. Functional requirements

### FR-1: Manual Add Peer

The Peers page must allow an administrator to enter `example.com`.

Mailnite must:

1. normalize the domain;
2. resolve `https://mail.example.com/.well-known/mail-key`;
3. validate the TLS connection and manifest;
4. create or update the Peer;
5. show a usable error without installing data if validation fails.

The normal Add Peer form must not accept a raw public key, sequence number,
manifest ID, or arbitrary URL.

### FR-2: DNS observation

When preparing outbound email for an unknown domain, Mailnite may query:

```text
_mailkey.<domain>
```

A syntactically valid MKDP1 TXT record schedules or performs deterministic HTTPS
resolution. DNS data never becomes the effective manifest.

### FR-3: Header observation

Mailnite recognizes:

```text
Mail-Key: v=MKDP1; d=example.com; id=<id>; mode=https
```

The header:

- is an asynchronous discovery or refresh hint;
- must not delay or reject the inbound email;
- must not directly install a public key;
- must not activate require-encryption policy by itself;
- must be rate-limited as a fetch trigger.

Mailnite must remove user-supplied `Mail-Key` fields from locally submitted
outbound messages and add the server-generated field.

### FR-4: Cached resolution

If a Peer has a valid, unexpired effective manifest, the outbound pipeline may
encrypt without network access.

Mailnite refreshes when:

- there is no effective manifest;
- the manifest is expired or nearing expiry;
- DNS or a header presents a different observed manifest ID;
- the administrator requests refresh.

### FR-5: Encryption before queue persistence

The outbound queue must receive only the encrypted destination envelope when
MKDP1 encryption is selected. SMTP delivery and retries must not perform
discovery or transform plaintext into ciphertext.

### FR-6: Delayed-message decryption

The receiving server maintains:

```text
kid → HSM handle
```

Retired private keys must be retained for at least:

```text
maximum manifest cache lifetime
+ maximum outbound delivery lifetime
+ clock-skew and operational margin
```

Only the current public key is returned by the well-known endpoint.

### FR-7: Safe failure

For a previously validated MKDP1 peer:

- use an unexpired cached manifest when available;
- otherwise attempt an HTTPS refresh;
- if no valid manifest is available, hold or fail the message according to
  explicit local policy;
- never silently send plaintext because DNS or HTTPS temporarily failed.

### FR-8: Peer removal

The default removal action is named **Forget Peer**.

It deletes cached manifests and observations but does not blacklist the domain.
The Peer may be rediscovered later through DNS, a header, or outbound demand.
The UI must warn that forgetting capability state can affect downgrade
protection.

An explicit **Disable MKDP for Domain** administrative policy may be added
separately. It must not be represented as ordinary Peer deletion.

## 7. Peers page requirements

The peer list displays:

- domain;
- state;
- effective manifest ID;
- effective `kid`;
- manifest expiration;
- last successful HTTPS verification;
- observed sources;
- encryption policy;
- last refresh error.

The peer details view displays:

- current manifest fields;
- historical accepted manifests;
- DNS and header observations;
- mismatched or stale observations;
- refresh history;
- active queue/decryption implications where available.

Actions:

- Add Peer;
- Refresh;
- Require Encryption;
- Return to Automatic Policy;
- Forget Peer.

## 8. Peer states

- `discovered` — an observation exists, but no manifest has been accepted.
- `active` — a valid effective manifest is available.
- `refreshing` — a refresh is in progress; a valid cached manifest may remain
  usable.
- `expired` — the effective manifest is expired and no replacement is
  available.
- `unavailable` — resolution failed and no usable manifest exists.
- `disabled` — administrator explicitly disabled MKDP for this domain.

## 9. Success metrics

- No externally supplied sequence numbers remain in MKDP1 manifests or
  envelopes.
- DNS/header observations can never replace an effective public key directly.
- A valid cache avoids network access in the normal outbound path.
- A rotated key is discovered without breaking delayed messages encrypted to an
  older `kid`.
- All effective manifests can be traced to a successful HTTPS validation or an
  explicitly separate future trust mode.
- No known MKDP1 peer silently downgrades to plaintext on temporary discovery
  failure.

## 10. Acceptance criteria

1. Adding `example.com` manually fetches only the deterministic HTTPS URL.
2. A header with a forged key is impossible because headers contain no key.
3. Different DNS and header IDs create observations and a refresh, not a
   winner-selection conflict.
4. A valid HTTPS response replaces the effective manifest atomically.
5. The sender and receiver independently calculate the same `kid`.
6. An envelope encrypted before a rotation can be decrypted after rotation by
   looking up the retired private key using `kid`.
7. Removing and re-observing a Peer behaves according to documented Peer
   lifecycle rules.
8. Canonical manifest and identifier test vectors pass in the public Go library
   and Mailnite.

