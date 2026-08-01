# Mail Key Discovery Protocol v1 (MKDP1)

Status: Draft 0.1  
Date: 2026-07-29  
Target implementation: `github.com/mailnite/mailkey`

## Decision summary

MKDP1 is a deliberately small protocol for discovering the current public
envelope-encryption key for an email domain before a message enters the outbound
delivery queue.

The central model is:

- A **Peer** represents one email domain, such as `example.com`.
- A **Manifest** is a versioned, cached description of that peer's current
  public encryption key and supported encryption suite.
- A Peer may retain multiple historical manifests, but exactly one valid
  manifest is effective for new outbound encryption.
- DNS, the `Mail-Key` email header, and a manual UI action are **discovery
  observations**. They do not directly install public keys.
- A successful, WebPKI-authenticated request to the deterministic HTTPS URL is
  the standard authority for an automatic MKDP1 peer:

  `https://mail.<domain>/.well-known/mail-key`

- A manual Add Peer action accepts a domain and performs the same HTTPS
  resolution. Manual public-key entry and manual manifest pinning are outside
  the MKDP1 MVP.
- There is no public sequence number, key ordering rule, key chain, Merkle log,
  witness protocol, gossip endpoint, or SMTP-time key discovery.
- `kid` is a deterministic content identifier for the domain, encryption suite,
  and public key. It is not an ordering value.
- `id` is the SHA-256 identifier of the canonical serialized manifest.
- The HTTPS response is canonical MessagePack produced by
  `go.arpabet.com/value`.

## Discovery examples

DNS:

```text
_mailkey.example.com. TXT "v=MKDP1; id=<BASE64URL_MANIFEST_ID>; mode=https"
```

Email:

```text
Mail-Key: v=MKDP1; d=example.com; id=<BASE64URL_MANIFEST_ID>; mode=https
```

Resolution:

```text
GET https://mail.example.com/.well-known/mail-key
```

Neither the DNS entry nor the header contains a public key. Their `id` values
are hints that allow a sender to reuse or refresh its local manifest cache.

## Documents

- `01-PRD.md` — product requirements and acceptance criteria.
- `02-MKDP1-PROTOCOL.md` — wire format and normative validation rules.
- `03-PEERS-AND-RESOLUTION.md` — Peers model, discovery sources, resolution
  state machine, and conflict semantics.
- `04-SECURITY.md` — trust boundary, downgrade behavior, and threat model.
- `05-GO-IMPLEMENTATION.md` — proposed Go packages and Mailnite integration.
- `06-TEST-PLAN.md` — unit, integration, interoperability, and security tests.
- `07-DOMAIN-IDENTITY.md` — PROPOSED extension: a long-lived Ed25519 domain
  identity that signs short-lived X25519 encryption epochs, so a sender that
  has met a domain once can verify later rotations without trusting the HTTPS
  authority again. Closes the limitation 04-SECURITY.md §6 records as accepted.

## Important implementation principle

The Peers page must not implement “maximum sequence wins” or “latest timestamp
wins.” The effective key is the key in the latest successfully validated
response from the deterministic HTTPS authority, subject to local administrative
policy and cache validity.

