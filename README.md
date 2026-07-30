# mailkey — Mail Key Discovery Protocol v1 (MKDP1)

Reference implementation of **MKDP1**: how a sending mail server discovers the
current public envelope-encryption key of a recipient email *domain*, before
the message is written to the outbound queue.

```go
import "github.com/mailnite/mailkey"
```

Specification: [`mailkey-mkdp1-spec/`](mailkey-mkdp1-spec/) ·
Security analysis: [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)

## The protocol in one page

One email domain has one **Peer**. A Peer's key lives in an immutable
**Manifest**, fetched from a single deterministic authority:

```
GET https://mail.example.com/.well-known/mail-key
```

The response is canonical MessagePack, authenticated by ordinary WebPKI TLS for
`mail.example.com`. That request is the **only** thing that can install a key.

DNS records and the `Mail-Key` mail header are **observations**. They say "this
domain speaks MKDP1, and the manifest I saw had this id" — they carry no key
material and can never install one:

```
_mailkey.example.com. TXT "v=MKDP1; id=<base64url>; mode=https"
Mail-Key: v=MKDP1; d=example.com; id=<base64url>; mode=https
```

Two identifiers do all the work:

| Identifier | Preimage | Job |
|---|---|---|
| `kid` | `SHA-256(pack(domain, alg, enc, pk))` | names the **key** — the receiver's direct private-key lookup |
| `manifest_id` | `SHA-256(canonical manifest bytes)` | names the **fetch** — provenance of one discovery result |

**There is no sequence number and no ordering rule.** That is the point of the
protocol, not an omission: the previous design let an unauthenticated observer
supply an integer that decided which key won, so one forged observation with a
huge value could freeze a domain's key rotation permanently. MKDP1 has no such
value — the current successful HTTPS response is authoritative, `issued_at` is
a sanity check and never a tie-break, and identifiers are never compared for
order.

## Packages

| Package | Contents |
|---|---|
| `mailkey` | the protocol's types and the interfaces a host application depends on |
| `mailkey/manifest` | canonical serialization, `kid` and `manifest_id`, validation |
| `mailkey/discovery` | domain normalization, derived names, DNS/header parsing |
| `mailkey/envelope` | the sealed message, with every identifier bound as AEAD associated data |

The root package is interfaces only — `Resolver`, `Store`, `Service`,
`PrivateKeyLookup`, `Publisher` — so a component-based application injects the
protocol rather than importing an implementation, and can supply its own
storage, HTTP stack or HSM without weakening any validation.

## Using it

Publish a domain's key:

```go
m, err := manifest.New(domain, now, now.Add(24*time.Hour),
    mailkey.AlgX25519, mailkey.EncAES256GCM, publicKey)
raw, err := manifest.Pack(m)          // serve these bytes verbatim
id := manifest.ManifestIDOf(raw)      // ETag, DNS record, Mail-Key header
```

Validate a fetched manifest (what a resolver does with a response body):

```go
m, err := manifest.ParseCanonical(body, "example.com")
err = manifest.Validate(m, time.Now(), manifest.DefaultLimits())
```

`ParseCanonical` decodes, checks the schema by exact field set and exact value
kinds, recomputes `kid`, then **repacks and requires byte-identical output**.
That last step enforces the whole canonical form — key order, integer widths,
string versus binary types — and rejects trailing bytes, without trusting the
decoder's strictness or touching the host application's global parser limits.

Seal a message once a manifest is validated:

```go
env, err := envelope.Seal(result, rfc5322Message)  // identifiers come from the result
raw, err := env.Marshal()
```

Open it on the receiving side:

```go
env, err := envelope.Unmarshal(raw)
key, err := lookup.FindPrivateKey(ctx, env.Header.Domain, env.Header.Kid)
plaintext, err := envelope.Open(key, env)
```

## Guarantees worth knowing

- **Names are derived, never accepted.** No MKDP1 object has a field that can
  specify a host, port, path or URL. Given a normalized domain, both the TXT
  name and the authority URL are fixed functions of it. A hostile `Mail-Key`
  header therefore cannot aim the resolver anywhere.
- **Envelope metadata is authenticated.** Recipient domain, `kid`,
  `manifest_id`, algorithm identifiers and the ephemeral key are bound as AEAD
  associated data. Rewriting any of them in flight produces an authentication
  failure, not a message that decrypts while describing itself falsely.
  (Mailnite's original envelope passed `nil` associated data; this is finding
  F-1 in the security review, and the reason the MKDP1 envelope carries its own
  suite identifier.)
- **Suites are named, never inferred.** `mkdp1-x25519-hkdf-sha256-aes256gcm`
  identifies the exact construction. Any change to derivation, nonce,
  associated data or cipher takes a new identifier.
- **Unknown is fatal.** Unknown versions, algorithms, modes and fields fail
  closed. Nothing here guesses.

## Interoperability

`manifest/manifest_test.go` pins the golden vectors — canonical bytes,
`manifest_id` and `kid` for a fixed fixture. A second implementation that
reproduces those bytes is compatible; one that does not, is not. Changing those
constants is a protocol change.

## Status

Draft. The wire format, identifiers and envelope suite are implemented and
pinned by vectors. The hardened HTTPS resolver, the Peer store and
reconciliation service, the glue components and the Mailnite integration are in
progress — see [`ROADMAP.md`](ROADMAP.md).

## License

Copyright 2022-present Karagatan LLC. All rights reserved.
