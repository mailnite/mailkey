# MKDP1 interoperability

This is the release gate of `mailkey-mkdp1-spec/06-TEST-PLAN.md` §10, and the
starting point for a second implementation.

## The published vectors

`testdata/vectors.json` is the artifact. It states its own inputs, so nothing in
it has to be taken on trust: every identifier can be recomputed from the fields
beside it. `TestPublishedManifestVectors` and `TestPublishedEnvelopeVector` do
exactly that on every run, which is what keeps the file from drifting away from
the code — published vectors that disagree with the implementation are worse than
none, because an implementer would chase a difference that is not in the protocol.

**Editing a value in that file is a protocol change.**

| Field | Meaning |
| --- | --- |
| `manifest.input` | the manifest to build: domain, validity, suite, public key |
| `manifest.canonical_bytes_hex` | the only acceptable encoding of that manifest |
| `manifest.manifest_id` | `SHA-256` of those bytes, base64url, unpadded |
| `manifest.kid` | `SHA-256` of the key descriptor — see below |
| `manifest.dns_txt_value` / `mail_key_header` | the two advertisement forms |
| `manifest.discovery_url` / `well_known_path` / `media_type` | the transport contract |
| `envelope.*` | a decrypt vector: private key, wire bytes, expected plaintext |
| `message.*` | the mail framing: header names, the placeholder Subject, the routing headers left in the clear, and a sealed message that must open to `inner` |

## What an implementation must reproduce

Two hashes, and they answer different questions:

```text
manifest_id = SHA-256(the exact bytes served)
              names the FETCH — provenance of one discovery result

kid         = SHA-256(canonical pack of the sorted map
                      {type: "mailkey-envelope-key-v1", domain, alg, enc, pk})
              names the KEY — independent of timestamps and of the manifest
              that carries it, which is why a receiver can look up a private
              key directly instead of trying every generation it holds
```

Canonical means: MessagePack, map keys sorted as byte strings, minimal integer
widths, text (`str`) and bytes (`bin`) as distinct types, no trailing data. A
parser must decode, **re-encode, and require byte-identical input** — for
manifests and for envelopes both. Without that check several byte strings decode
to one object, and since the envelope's associated data is computed from the
parsed fields, the bytes on the wire would not be pinned by the tag protecting
them.

The envelope vector is a *decrypt* vector, and that is forced rather than chosen:
every envelope carries a fresh ephemeral key and nonce, so no implementation can
reproduce another's bytes. Being able to *open* them is the property that matters,
and it transitively checks the whole suite — the header fields are authenticated
as associated data, so any disagreement about them shows up as a failed tag.

## Two independent implementations

The gate asks for at least two independent processes producing the same bytes and
identifiers. Both halves run in Mailnite's e2e ladder (`e2e/mailkey.mjs`):

- the **Go implementation** in this repository, serving a live authority;
- an **independent JavaScript implementation**
  (`mailnite/e2e/mkdp1-independent.mjs`), hand-written from the protocol
  description, dependency-free, sharing no code with the server. It decodes the
  served MessagePack, re-encodes it, requires the bytes to match, derives both
  identifiers, and checks the `kid` against the key material it names.

Reaching for a MessagePack library there would have tested that library's
agreement with Go's, not the protocol's clarity — so the packer is written out.
It runs against a runtime-generated key and again after a rotation, so the
agreement is not an artifact of a fixture.

## Gate status

| §10 requirement | Where it is checked |
| --- | --- |
| Mailnite and `mailkey` pass identical manifest vectors | `TestPublishedManifestVectors`; `pkg/server` `TestPublishThenSealThenOpen` |
| Two independent processes agree on bytes and IDs | `e2e/mailkey.mjs` + `mkdp1-independent.mjs`, live server |
| Receiver key generation and sender calculation agree on `kid` | `TestPublishedEnvelopeVector`; `TestKidLookupIsDerivedNotStored` |
| Envelope crypto vectors published and verified | `testdata/vectors.json`, `TestPublishedEnvelopeVector` |
| Upgrade tests prove old `kid` mappings stay decryptable | `TestRotationKeepsDelayedMailReadable`; retention floor tests |
| Peers UI matches documented source and conflict semantics | `TestOneDomainIsOnePeer`; the Peers page shows state/kid/manifest id/expiry/verified/sources/policy/last error |

## Fuzzing

Seven parsers, each with the property that matters rather than just "no panic":

| Target | Property |
| --- | --- |
| `FuzzParseCanonical` | accepted input repacks identically; `kid` recomputes |
| `FuzzDecodeID` | one canonical spelling per identifier |
| `FuzzNormalize` | accepted domains are safe to derive a URL from, and idempotent |
| `FuzzParseHeader` | containment: at most a manifest id, never a key or a location |
| `FuzzParseDNS` | same, plus one bad record never hides a good one |
| `FuzzUnmarshal` (envelope) | accepted bytes are canonical |
| `TestDecodeBombIsBounded` | bounded memory on tiny inputs claiming huge structures |

Fuzzing has found three real defects that hand-written tests missed: `Normalize`
was not idempotent (F-11), base64url identifiers had multiple spellings (F-12),
and the envelope parser accepted non-canonical encodings — found while writing
this gate. Corpora are committed under `testdata/fuzz/` as regression seeds.

## The three headers

```text
Mail-Key            v=MKDP1; d=<domain>; id=<manifest id>; mode=https
Mail-Key-Encrypted  MKDP1                  — what sealed this message
Mail-Key-Suite      mkdp1-x25519-…         — which parser opens it
```

None carries an `X-` prefix. RFC 6648 deprecated that convention in 2012 for
exactly this case: the prefix means "experimental", it becomes permanent the
moment anything deploys it, and standardising then forces a rename every
implementation must follow. A protocol meant to be implemented more than once
should not begin by naming itself provisional.

They are also not named after any product. A header saying which SOFTWARE sealed
a message tells a reader the one thing about it that carries no meaning.

## Known limitations

Stated because an implementer will otherwise assume otherwise:

- **No certificate transparency check and no pinned signing key.** Authority
  trust is WebPKI plus the fetch host, nothing more (F-10).
- **No ordering rule, deliberately.** There is no sequence number and no
  "newest wins": an authority that alternates between two valid manifests is
  reported as unstable for a human to resolve. Inventing a tie-break here would
  be inventing a rule an attacker could aim.
- **Advertisements are hints.** A DNS record or a mail header can only ever cause
  a fetch. Neither can install a key, so neither needs to be authenticated.
