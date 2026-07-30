# MKDP1 Protocol Specification

Status: Draft 0.1

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used as
normative requirements.

## 1. Domain normalization

Before discovery, an implementation MUST normalize an email domain to:

- an ASCII IDNA A-label;
- lowercase;
- no trailing dot;
- no scheme, port, path, user information, wildcard, or IP literal.

The normalized email domain is called `d`.

For `d = example.com`, the discovery hostname is always:

```text
mail.example.com
```

## 2. DNS advertisement

The DNS owner name is:

```text
_mailkey.<d>
```

The MKDP1 TXT value is:

```text
v=MKDP1; id=<base64url manifest ID>; mode=https
```

Rules:

- `v` MUST equal `MKDP1`.
- `mode` MUST equal `https`.
- `id` MUST decode as exactly 32 bytes using unpadded base64url.
- A malformed record MUST be ignored and recorded diagnostically.
- Multiple different valid records MUST be recorded as inconsistent DNS
  observations and MUST trigger HTTPS resolution.
- DNS data MUST NOT install a key or manifest.

## 3. Email advertisement

The field syntax is:

```text
Mail-Key: v=MKDP1; d=example.com; id=<base64url manifest ID>; mode=https
```

Rules:

- `d` is the normalized email domain, not `mail.example.com`.
- The HTTPS hostname is derived as `mail.<d>`.
- The header MUST NOT contain a public key.
- The header MUST NOT contain an arbitrary URL, hostname, or port.
- Unknown versions or modes MUST be ignored.
- A header is an untrusted observation and MUST NOT install a manifest.
- A receiver SHOULD bound and rate-limit header-triggered discovery.
- A Mailnite server SHOULD strip locally supplied `Mail-Key` fields and add its
  own field during final outbound message preparation.

## 4. HTTPS endpoint

The only MKDP1 URL for `d` is:

```text
https://mail.<d>/.well-known/mail-key
```

The client MUST:

- use HTTPS;
- perform normal WebPKI chain and hostname validation;
- require the certificate identity for `mail.<d>`;
- send `GET`;
- reject redirects;
- reject authentication prompts;
- impose connection, header, and body timeouts;
- limit the response body to 16 KiB;
- require HTTP status `200`.

Recommended media type:

```text
application/msgpack
```

A client SHOULD accept any MessagePack spelling (and an empty or
`application/octet-stream` type), because the media type is a hint: what decides
whether a response is a manifest is the canonical parse.

The server SHOULD return:

```text
Cache-Control: max-age=<seconds>, must-revalidate
```

The effective cache lifetime MUST NOT exceed the manifest's `expires_at`.

## 5. Canonical serialization

The response body is the canonical MessagePack byte stream produced by
`value.Pack` from `go.arpabet.com/value`.

MKDP1 permits only:

- UTF-8 string map keys;
- UTF-8 string values;
- raw byte strings;
- signed 64-bit integers;
- booleans;
- dense lists;
- maps.

MKDP1 does not permit floats, decimals, big integers, sparse lists, extension
values, duplicate map keys, or schema values outside documented bounds.

A client MUST:

1. read the bounded raw body;
2. unpack it;
3. validate the MKDP1 schema;
4. repack it canonically;
5. require the repacked bytes to exactly equal the received bytes.

JSON output is diagnostic only and MUST NOT be hashed.

## 6. Manifest

The logical schema is:

```text
{
  "v":          "MKDP1",
  "domain":     <UTF-8 normalized d>,
  "issued_at":  <int64 Unix seconds>,
  "expires_at": <int64 Unix seconds>,
  "key": {
    "kid": <Raw 32 bytes>,
    "alg": <UTF-8 registered algorithm identifier>,
    "enc": <UTF-8 registered encryption identifier>,
    "pk":  <Raw public-key bytes>
  }
}
```

Initial algorithm identifiers:

```text
alg = "x25519"
enc = "aes256gcm"
```

MKDP1 discovers the key and names the existing Mailnite envelope suite. The
public `mailkey` repository MUST separately publish the exact existing key
derivation, ephemeral-key, nonce, envelope, and associated-data construction as
interoperability test vectors. If that construction is changed to HPKE, it MUST
receive a distinct algorithm/suite identifier.

Validation rules:

- `domain` MUST exactly equal requested `d`.
- `issued_at` MUST be no later than the allowed future clock-skew boundary.
- `expires_at` MUST be later than `issued_at`.
- The validity interval MUST NOT exceed the implementation's configured MKDP1
  maximum.
- `pk` length and encoding MUST match `alg`.
- `kid` MUST equal the independently calculated key ID.
- Unknown required fields, algorithms, or encryption modes MUST fail closed.

`issued_at` is not a sequence and MUST NOT be used as a “maximum wins” value.

## 7. Key identifier

The sender and receiver calculate `kid` independently.

Construct this canonical `value` object:

```text
{
  "type":   "mailkey-envelope-key-v1",
  "domain": <normalized d>,
  "alg":    <manifest alg>,
  "enc":    <manifest enc>,
  "pk":     <Raw public-key bytes>
}
```

Then:

```text
kid = SHA-256(value.Pack(KeyDescriptor))
```

Rules:

- Binary protocol objects carry `kid` as 32 raw bytes.
- UI and text protocols use unpadded base64url.
- Implementations MUST use the full 32-byte value.
- On generation/import, the receiver stores `kid → private-key/HSM handle`.
- On discovery, the sender MUST recompute `kid` and reject a mismatch.
- If one `kid` is associated with different key descriptors, processing MUST
  fail as a critical integrity error; an existing mapping MUST NOT be
  overwritten.

## 8. Manifest identifier

For canonical response bytes `manifest_bytes`:

```text
manifest_id = SHA-256(manifest_bytes)
```

Rules:

- Binary objects carry the raw 32 bytes.
- DNS and email headers carry unpadded base64url.
- The manifest does not contain its own `manifest_id`.
- The computed ID is the authoritative ID for the fetched object.

## 9. Envelope binding

The encrypted envelope MUST carry:

- protocol/envelope version;
- normalized recipient domain;
- `kid`;
- `manifest_id`;
- encryption algorithm identifiers;
- the encryption scheme's required encapsulation data;
- ciphertext.

The domain, `kid`, `manifest_id`, algorithm identifiers, and encapsulation
metadata MUST be cryptographically authenticated by the existing envelope
construction as associated data or as part of its authenticated payload.

`kid` performs private-key lookup. `manifest_id` records the complete discovery
manifest used by the sender.

## 10. Rotation

The HTTPS endpoint returns only the current manifest.

When rotating:

1. generate/import the new receiver key;
2. calculate its `kid` and persist the HSM mapping;
3. atomically publish the new manifest;
4. retain the previous private key for the required retention interval.

The sender MAY use any unexpired manifest already accepted through HTTPS. This
means the receiver MUST expect delayed messages addressed to recently retired
keys.

No public sequence number or public history is required.

## 11. Versioning

Clients MUST accept only `MKDP1` objects they understand. A future incompatible
schema, trust model, or encryption construction uses another version or a new
registered suite identifier. Implementations MUST NOT guess how to process an
unknown version.

