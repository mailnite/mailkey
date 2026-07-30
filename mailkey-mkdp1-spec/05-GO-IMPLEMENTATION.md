# Go Implementation Design

Target module:

```text
github.com/mailnite/mailkey
```

Canonical value dependency:

```text
go.arpabet.com/value
```

## 1. Package boundaries

```text
mailkey/
  manifest/     schema, Pack/Unpack, ID and kid calculation
  discovery/    DNS and Mail-Key header parsing
  resolver/     deterministic HTTPS resolution and validation
  peer/         source-neutral Peer state and reconciliation
  envelope/     identifiers and integration with existing crypto envelope
  testvector/   stable cross-process protocol fixtures
```

The reusable library should not depend on Badger, a particular HSM, Mailnite UI,
or SMTP implementation.

## 2. Public types

Illustrative API:

```go
type Manifest struct {
    Version   string
    Domain    string
    IssuedAt  time.Time
    ExpiresAt time.Time
    Key       KeyDescriptor
}

type KeyDescriptor struct {
    Kid       [32]byte
    Algorithm string
    Encryption string
    PublicKey []byte
}

type ManifestID [32]byte
type KeyID [32]byte

type ObservationSource string

const (
    SourceDNS    ObservationSource = "dns"
    SourceHeader ObservationSource = "header"
    SourceManual ObservationSource = "manual"
)
```

## 3. Manifest API

```go
func Pack(m Manifest) ([]byte, error)
func ParseCanonical(raw []byte, requestedDomain string) (Manifest, error)
func ManifestIDOf(rawCanonical []byte) ManifestID

func CalculateKeyID(
    domain string,
    algorithm string,
    encryption string,
    publicKey []byte,
) (KeyID, error)

func (m Manifest) Validate(now time.Time, limits Limits) error
```

`ParseCanonical` must decode, validate, repack, and compare exact bytes.

## 4. Discovery API

```go
type Advertisement struct {
    Version    string
    Domain     string
    ManifestID ManifestID
    Mode       string
}

func ParseDNS(domain string, txt []string) ([]Advertisement, error)
func ParseHeader(value string) (Advertisement, error)
func FormatHeader(domain string, id ManifestID) string
func DNSName(domain string) (string, error)
func DiscoveryURL(domain string) (*url.URL, error)
```

`DiscoveryURL` must not accept a supplied host or URL. It derives the complete
URL from the normalized domain.

## 5. Resolver API

```go
type Resolver interface {
    Resolve(ctx context.Context, domain string, opts ResolveOptions) (Result, error)
}

type Result struct {
    Manifest    Manifest
    ManifestID  ManifestID
    Raw         []byte
    FetchedAt   time.Time
    ExpiresAt   time.Time
    TLSHost     string
}
```

The default resolver owns:

- domain normalization;
- deterministic URL construction;
- TLS/WebPKI validation;
- redirect rejection;
- HTTP limits and timeouts;
- canonical parsing;
- manifest and `kid` validation.

The resolver should expose dependency injection for DNS and HTTP clients so
Mailnite and tests can provide controlled implementations without weakening
default validation.

## 6. Peer API

```go
type Store interface {
    GetPeer(ctx context.Context, domain string) (*Peer, error)
    PutObservation(ctx context.Context, domain string, o Observation) error
    InstallManifest(ctx context.Context, domain string, r Result) error
    ForgetPeer(ctx context.Context, domain string) error
}

type Service interface {
    ObserveDNS(ctx context.Context, domain string, txt []string) error
    ObserveHeader(ctx context.Context, headerValue string) error
    AddPeer(ctx context.Context, domain string) (Peer, error)
    Refresh(ctx context.Context, domain string) (Peer, error)
    ResolveForEncryption(ctx context.Context, domain string) (Result, error)
}
```

`InstallManifest` must atomically:

1. persist the immutable manifest;
2. move the existing effective manifest to historical state;
3. set the new effective manifest;
4. reconcile observations;
5. update Peer status.

## 7. HSM and receiver integration

The library should expose an interface rather than own the HSM:

```go
type PrivateKeyLookup interface {
    FindPrivateKey(ctx context.Context, domain string, kid KeyID) (KeyHandle, error)
}
```

For migration from the current sequence lookup:

```text
kid → legacy seq → HSM key
```

The external envelope contains only `kid`. The internal sequence may remain
until the HSM schema is migrated.

Key generation flow:

1. generate X25519 key in or for the HSM;
2. obtain the public key;
3. calculate `kid`;
4. persist a unique mapping;
5. build and publish the canonical manifest.

## 8. Mailnite outbound integration

Suggested pipeline:

```text
accepted local message
→ recipient-domain grouping
→ ResolveForEncryption(domain)
→ envelope encryption
→ persist encrypted envelope
→ delivery queue
→ SMTP/direct relay attempts
```

No resolver call occurs inside SMTP delivery attempts.

To prevent duplicate HTTPS work, use a per-domain single-flight mechanism and
persist cache state in the Peers store.

## 9. Mailnite inbound integration

Encrypted input:

```text
parse bounded envelope
→ validate domain and identifiers
→ lookup kid
→ decrypt and authenticate
→ store/process decrypted message according to Mailnite policy
```

Normal email:

```text
accept message
→ parse bounded Mail-Key header
→ append observation
→ enqueue optional asynchronous resolution
```

Header discovery must not run as an unbounded goroutine per message.

## 10. HTTP server integration

Mailnite serves:

```text
GET /.well-known/mail-key
```

The handler should:

- read the prebuilt canonical manifest from immutable/atomic state;
- set the MKDP1 media type;
- set bounded cache headers;
- set `ETag` from the base64url manifest ID;
- write canonical bytes without reserializing them per request;
- expose only the current public manifest.

Publication should be atomic: clients must never observe a manifest referring to
a key before the receiver can resolve that `kid` to the private key.

## 11. Configuration

Suggested settings:

```text
mkdp.enabled
mkdp.discovery.dns_enabled
mkdp.discovery.header_enabled
mkdp.resolver.timeout
mkdp.resolver.max_body_bytes
mkdp.resolver.refresh_before_expiry
mkdp.resolver.max_manifest_lifetime
mkdp.queue.fail_closed_for_known_peers
mkdp.receiver.retired_key_retention
mkdp.security.allow_private_discovery_targets
```

Defaults should reject private discovery targets unless the administrator opts
into a private/split-DNS deployment.

## 12. Version and compatibility discipline

The `mailkey` repository should publish:

- the normative schema;
- canonical binary test vectors;
- expected manifest IDs and `kid` values;
- malformed object fixtures;
- envelope cryptography test vectors;
- a compatibility policy for `value` wire-format dependencies.

The protocol should use only the portable subset of `value` documented in the
MKDP1 specification. A dependency update must not change established vectors.

