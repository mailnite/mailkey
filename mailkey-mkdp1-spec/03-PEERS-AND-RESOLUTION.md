# Peers, Discovery Sources, and Resolution

## 1. Peer definition

A Peer is a local Mailnite record keyed by normalized email domain.

It aggregates:

- administrative delivery policy;
- one effective accepted manifest;
- optional historical accepted manifests;
- untrusted discovery observations;
- refresh status and errors.

A Peer MUST NOT be duplicated because DNS, a header, and an administrator all
observed the same domain. Those are observations attached to one Peer.

## 2. Recommended data model

```text
Peer {
    domain
    state
    encryption_policy

    effective_manifest_id?
    last_verified_at?
    next_refresh_at?
    last_error?

    manifests[]
    observations[]
}

ManifestRecord {
    manifest_id
    canonical_bytes
    kid
    issued_at
    expires_at
    fetched_at
    authority_host
    tls_verified
    status: effective | historical | rejected
}

Observation {
    source: dns | header | manual
    observed_manifest_id?
    observed_at
    expires_at?
    status: pending | confirmed | stale | malformed | inconsistent
    context?
}
```

`context` should be privacy-minimized. For a header, it may contain an internal
message reference, but the Peer record should not duplicate message content or
unnecessary sender information.

## 3. Source semantics

### 3.1 DNS

DNS is a capability and cache-change hint.

- Matching cached ID: no immediate refresh is required.
- Different ID: refresh through HTTPS.
- Several different DNS IDs: mark DNS inconsistent and refresh through HTTPS.
- Missing DNS after capability was previously verified: do not delete or
  downgrade the Peer automatically.

### 3.2 `Mail-Key` header

The header is a capability and cache-change hint useful for future mail or
replies.

- Matching cached ID: mark the observation confirmed.
- Different ID: schedule HTTPS refresh.
- Stale ID from a delayed message: record as stale after HTTPS validation.
- Invalid or unrelated domain: ignore or record as malformed.

The inbound message path must not wait for this refresh.

### 3.3 Manual Add Peer

The administrator enters only a domain.

Manual addition:

- creates a pending observation;
- immediately calls the same standard HTTPS resolver;
- does not establish a separate cryptographic authority;
- does not bypass TLS or manifest validation.

Manual raw-key or raw-manifest pinning is not part of the MKDP1 MVP. If added
later, it must be a visibly separate trust mode rather than another observation
source.

## 4. Standard resolver

Every automatic source converges on:

```text
Resolve("example.com")
    → GET https://mail.example.com/.well-known/mail-key
    → validate TLS
    → validate canonical manifest
    → calculate manifest_id and kid
    → atomically install effective manifest
```

### Resolution triggers

Resolve when:

- an administrator adds or refreshes a Peer;
- a syntactically valid DNS advertisement is observed for an unknown Peer;
- a valid header advertises an unknown Peer;
- an observed ID differs from the effective manifest ID;
- the effective manifest is expired or near expiry;
- outbound encryption requires a key and no usable cached manifest exists.

### Resolution deduplication

Concurrent triggers for the same domain MUST coalesce into one in-flight HTTPS
request. DNS and header input must not create an unbounded fetch queue.

## 5. Resolution algorithm

```text
Resolve(domain, reason):
    d = Normalize(domain)
    peer = LoadOrCreatePeer(d)

    if peer is administratively disabled:
        return Disabled

    if effective manifest is valid
       and refresh is not forced
       and no new observed ID differs:
        return effective manifest

    coalesce with any in-flight resolution for d

    response = HTTPS GET deterministic URL
    if request or validation fails:
        record error
        if existing effective manifest remains valid:
            return existing effective manifest
        return Unavailable

    manifest = validate canonical response
    mid = SHA256(response body)
    kid = calculate key ID

    persist manifest record
    atomically set it effective
    mark preceding effective manifest historical
    reconcile observations against mid
    return manifest
```

## 6. Are differing sources conflicts?

Usually, no.

DNS and headers may be stale because of DNS TTLs, delayed email, forwarding, or
rotation. Their IDs are observations, not candidate keys.

### Observation mismatch

Example:

```text
cached HTTPS ID = A
DNS ID          = B
header ID       = C
```

Required behavior:

1. record B and C;
2. fetch the deterministic HTTPS URL;
3. install fetched ID D if valid;
4. classify observations:
   - equal to D: confirmed;
   - different from D: stale or inconsistent.

There is no “maximum,” voting, or source-precedence selection between A, B, and
C.

### Normal HTTPS rotation

If a later successful fetch returns a different valid manifest ID, it is a
rotation or policy update, not automatically a conflict.

The old manifest becomes historical and remains available for diagnostics. The
receiver separately retains the corresponding old private key.

### Actual protocol errors

Treat these as errors:

- HTTPS manifest domain differs from requested domain;
- manifest `kid` does not match the deterministic calculation;
- one `kid` maps to different key descriptors;
- one manifest ID appears with different bytes;
- endpoint repeatedly alternates between manifests over a short interval;
- fetched manifest is already expired or has an invalid validity interval;
- unsupported algorithm identifiers;
- noncanonical MessagePack response.

Repeated HTTPS alternation should appear as an **authority instability warning**,
not be resolved through timestamp or numeric ordering.

## 7. Peer state transitions

```text
observation/manual add
        |
        v
   discovered ----resolution failure----> unavailable
        |
   valid HTTPS manifest
        |
        v
      active ----refresh starts----> refreshing
        ^                              |
        |------valid replacement-------|
        |
        +----valid cached manifest remains usable

active ----manifest expires and refresh fails----> expired

any state ----administrator disables----> disabled
```

## 8. Outbound pipeline

Before persisting an outbound message:

1. group recipients by destination domain;
2. obtain a valid effective manifest for each selected MKDP1 destination;
3. encrypt the envelope;
4. include `kid` and `manifest_id`;
5. persist only the encrypted result;
6. hand the encrypted envelope to ordinary SMTP delivery and retry logic.

SMTP relays do not need MKDP1 awareness.

If one message targets several domains, the implementation may create separate
domain delivery envelopes or wrap one content-encryption key independently for
each destination. That is an envelope-format decision, not a discovery-source
decision.

## 9. Inbound pipeline

For an encrypted envelope:

1. normalize and validate the embedded recipient domain;
2. locate the local domain configuration;
3. resolve `kid` to an HSM/private-key handle;
4. authenticate and decrypt the envelope;
5. retain `manifest_id` in security metadata for audit and diagnostics;
6. process spam detection, classification, simplification, indexing, and
   embedding only after successful decryption.

For a plaintext or decrypted message containing `Mail-Key`, create an
observation asynchronously.

## 10. Peers page behavior

### Add

Input:

```text
Domain: example.com
```

The UI displays resolution progress and creates an active Peer only after
successful manifest validation. A failed manual attempt may remain as an
unavailable Peer so the administrator can inspect and retry it.

### Refresh

Forces standard HTTPS resolution. It does not prefer DNS or header values.

### Forget

Removes local observations and cached public manifests after confirmation.
Already encrypted queued messages are unaffected because they carry `kid` and
`manifest_id`.

The domain can reappear through later discovery.

### Require encryption

Persists a local fail-closed policy. If no valid manifest is available, future
messages wait or fail rather than being stored or delivered as plaintext.

## 11. Suggested UI wording

Use:

- “Discovered through DNS”
- “Observed in Mail-Key header”
- “Added manually; verified through HTTPS”
- “Effective manifest verified through HTTPS”
- “Observed ID differs; refresh required”
- “Stale observation”
- “Authority returned changing manifests”

Avoid:

- “DNS key”
- “Header key”
- “Manual key”
- “Highest sequence”
- “Header won”
- “DNS conflict” when the condition is only a stale ID.

