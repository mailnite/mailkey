/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package mailkey is the reference implementation of the Mail Key Discovery
Protocol version 1 (MKDP1): how a sending mail server learns the CURRENT
public envelope-encryption key of a recipient email domain, before the message
is persisted in the outbound queue.

MKDP1 in three sentences. One email domain has one Peer record; a Peer's
effective key lives in an immutable, cached Manifest. The only authority that
can install a manifest is an authenticated HTTPS GET of a deterministic URL —
https://mail.<domain>/.well-known/mail-key — validated against the public web
PKI. DNS records and the Mail-Key mail header are OBSERVATIONS: they say "this
domain speaks MKDP1, and the manifest I saw had this id", they never carry a
key, and they can never install one.

What the protocol deliberately does not have: sequence numbers, key ordering,
"newest wins", transparency logs, witnesses, or SMTP-time discovery. An
ordering value suppliable by an unauthenticated observer is an attack surface
(a forged maximum freezes rotation forever) — MKDP1 has no such value. See
SECURITY-REVIEW.md.

This root package declares the types and interfaces the protocol is expressed
in; the subpackages implement them:

	manifest   the wire schema, canonical serialization, ManifestID and KeyID
	discovery  DNS/header advertisement parsing, domain normalization, URL derivation
	resolver   the hardened HTTPS authority client
	peer       source-neutral Peer state and observation reconciliation
	envelope   the sealed message envelope, with MKDP1 identifiers bound as AAD
	component  optional glue beans, for dependency-injection applications

The interfaces here are the integration seam: a host application depends on
Resolver, Store, Service and PrivateKeyLookup, not on the implementations, so
it can substitute its own storage, its own HTTP stack, or an HSM without
weakening the protocol's validation.
*/
package mailkey

import (
	"context"
	"reflect"
	"time"
)

// Interface classes, for dependency-injection containers that resolve beans by
// interface type. A host looks the protocol up by what it DOES, never by which
// implementation happens to provide it.
var (
	ResolverClass         = reflect.TypeOf((*Resolver)(nil)).Elem()
	StoreClass            = reflect.TypeOf((*Store)(nil)).Elem()
	ServiceClass          = reflect.TypeOf((*Service)(nil)).Elem()
	PrivateKeyLookupClass = reflect.TypeOf((*PrivateKeyLookup)(nil)).Elem()
	PublisherClass        = reflect.TypeOf((*Publisher)(nil)).Elem()
)

// Version is the protocol version token carried by every MKDP1 object.
const Version = "MKDP1"

// Mode is the only discovery mode in MKDP1: resolve over HTTPS.
const Mode = "https"

// SubjectQueryParam is the query parameter naming the SUBJECT domain on every
// authority fetch (?d=…). It is sent on every request — self-hosted included —
// so one host can serve many domains' manifests (delegated authority) with a
// single uniform request shape.
const SubjectQueryParam = "d"

// MaxAuthorityEntries bounds the manifest's signed authority sequence. Two is
// the working need (a primary-domain switch keeps both generations green);
// four leaves headroom without opening an amplification list.
const MaxAuthorityEntries = 4

// HeaderName is the mail header that advertises MKDP1 capability.
const HeaderName = "Mail-Key"

// HeaderEncrypted marks a message whose body is an MKDP1 envelope. Its value is
// the protocol version, so a reader learns WHICH protocol sealed the message
// rather than merely that something did.
const HeaderEncrypted = "Mail-Key-Encrypted"

// HeaderSuite records the ciphersuite the envelope uses, so a receiver chooses
// its parser from what the message declares instead of trying formats in turn.
const HeaderSuite = "Mail-Key-Suite"

/*
The three detached-proof fields on the well-known HTTPS RESPONSE. They are not
mail headers and never appear on a message.

The proof is detached rather than embedded because the deployed manifest parser
requires an exact field set — an extra "signature" key inside the object would be
rejected by every client already in the field. Keeping it outside means the
manifest bytes are unchanged, manifest_id keeps its value and meaning, old
clients validate exactly as before, and new clients get authentication for the
cost of three response fields.

All three or none: a subset is MALFORMED, not absent, because "the signature is
missing" and "the signature is wrong" must never look the same. And the signer
fingerprint is a CLAIM to check, never a value to trust — a verifier recomputes
it from the supplied public key and rejects a mismatch, so a server cannot name a
fingerprint its own key does not produce.
*/
const (
	// HeaderIdentity carries the Ed25519 identity public key as
	// "ed25519:<unpadded base64url>". Key material may travel only here — never
	// in DNS, never in a mail header.
	HeaderIdentity = "Mail-Key-Identity"
	// HeaderSigner carries the identity fingerprint, unpadded base64url.
	HeaderSigner = "Mail-Key-Signer"
	// HeaderSignature carries the 64-byte Ed25519 signature, unpadded base64url.
	HeaderSignature = "Mail-Key-Signature"
)

/*
None of the three carries an "X-" prefix, deliberately.

RFC 6648 deprecated that convention in 2012, and for the situation this protocol
is in: the prefix is meant to say "experimental", it becomes permanent the moment
anything deploys it, and standardising then forces a rename that every
implementation has to follow (X-Forwarded-For → Forwarded is the well-known
casualty). A protocol that intends to be implemented more than once should not
start by naming itself provisional.

They are also not named after the product. A header called X-Mailnite-Encrypted
would tell a reader which SOFTWARE sealed the message, which is the one thing
about it that carries no meaning; Mail-Key-Encrypted names the protocol, which
is what another implementation needs to know.
*/

// DNSPrefix is the label prefixed to a domain to form the TXT owner name.
const DNSPrefix = "_mailkey"

// HostPrefix is the label prefixed to a domain to form the discovery host.
const HostPrefix = "mail"

// WellKnownPath is the fixed path of the discovery endpoint.
const WellKnownPath = "/.well-known/mail-key"

// MediaType is the content type of the discovery response.
//
// The generic MessagePack type rather than a vendor-specific one: a manifest IS
// canonical MessagePack, and nothing about reading it depends on knowing who
// specified the schema. A vendor tree would also imply the format belongs to one
// implementation, which is the opposite of the point — and it makes ordinary
// tooling (proxies, caches, curl) treat the response as something exotic.
const MediaType = "application/msgpack"

// MaxBodyBytes bounds a discovery response before it is allocated.
const MaxBodyBytes = 16 << 10

// Registered algorithm and encryption identifiers. These name the key TYPE and
// the bulk cipher in the manifest; the exact construction that consumes them
// (key derivation, nonce, associated data) is identified by the envelope's own
// suite — see the envelope package.
const (
	AlgX25519    = "x25519"
	EncAES256GCM = "aes256gcm"
)

// ManifestID is SHA-256 of the canonical manifest bytes: the identity of one
// immutable fetched manifest. DNS and headers carry it as unpadded base64url.
type ManifestID [32]byte

// KeyID ("kid") is SHA-256 of the canonical key descriptor — domain, alg, enc
// and public key. It is a deterministic CONTENT identifier, computed
// independently by sender and receiver, and used by the receiver for direct
// private-key lookup. It is not, and must never be used as, an ordering value.
type KeyID [32]byte

/*
Fingerprint ("fp") is SHA-256 of a domain's canonical IDENTITY descriptor —
type, domain, algorithm and Ed25519 public key. See the identity package.

It is the longest-lived of the three identifiers and the only one a sender keeps
across rotations, because it is the only one that answers "is this still the same
authority". The other two answer narrower questions:

	fp           the peer's trust anchor          years    pinned
	kid          which key to seal to             days     follows rotation
	manifest_id  which fetch this was             hours    provenance only

Conflating them is the failure this extension exists to prevent: a manifest_id
treated as a trust decision makes every re-issue look like a new authority, and a
kid treated as one makes every routine key rotation an alarm.
*/
type Fingerprint [32]byte

// KeyDescriptor is the key half of a manifest: what KeyID is computed over.
type KeyDescriptor struct {
	Kid        KeyID
	Algorithm  string
	Encryption string
	PublicKey  []byte
}

// Manifest is a domain's current published key, as fetched and validated.
// Manifests are immutable: a new one replaces the effective manifest whole.
type Manifest struct {
	Version   string
	Domain    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Key       KeyDescriptor
	// Authority is the domain's CONSENT to be served elsewhere: the authority
	// domains whose mail hosts may serve this manifest. Empty means only the
	// domain's own host may (the self-hosted default).
	//
	// It is inside the signed, id-hashed bytes on purpose. A record's a= can
	// misroute a request; this list decides whether what comes back is
	// acceptable — so a hostile pointer reaches a host that either 404s or
	// returns a manifest whose consent does not name it, and a manifest
	// stolen and re-served from elsewhere fails the same check. Delegation is
	// thereby granted by the domain itself, never by an observation.
	//
	// A SEQUENCE, not a single value, because a primary-domain switch must
	// keep both DNS generations working while zones converge: [new, old]
	// during the transition, pruned to [new] when it completes.
	Authority []string
}

// Source is where an observation came from. Sources have different operational
// origins and NO different cryptographic weight: none of them installs a key.
type Source string

const (
	SourceDNS    Source = "dns"
	SourceHeader Source = "header"
	SourceManual Source = "manual"
)

// Advertisement is a parsed observation: a claim that a domain speaks MKDP1,
// and optionally the manifest id the observer saw. It carries no key material.
type Advertisement struct {
	Version string
	Domain  string
	// Authority is the DELEGATED authority domain from the a= field — the
	// domain whose mail host serves this domain's manifests (x-primary-domain
	// delegation). Empty means self-hosted: the authority is Domain itself.
	// Like every observation field it is untrusted. It MUST NOT select the route
	// on first contact; only an established identity pin (or a separate
	// authenticated local policy) can make an observed delegation eligible.
	Authority  string
	ManifestID ManifestID
	HasID      bool
	// Fingerprint is the domain's advertised signing identity. An OBSERVATION:
	// it can corroborate a pin or contest one, and it can never install one —
	// which is also why the record carries a fingerprint and never a public key.
	Fingerprint Fingerprint
	HasFP       bool
	Mode        string
}

// Result is one successful authority fetch: the validated manifest plus the
// exact bytes it was validated from (the bytes ARE the identity — never
// re-serialize them to recompute the id).
type Result struct {
	Manifest   Manifest
	ManifestID ManifestID
	Raw        []byte
	FetchedAt  time.Time
	ExpiresAt  time.Time
	TLSHost    string
	// Proof is the detached identity signature the authority served, verified
	// as internally consistent (the signer is the fingerprint of the supplied
	// key, and the signature covers Raw). nil when the domain published none.
	//
	// Internally consistent is NOT trusted: whether this signer is the identity
	// this sender pins for the domain is decided against the peer's pin, not
	// here. An attacker's own proof is internally consistent too.
	Proof *Proof
	// ProofError records a proof that was PRESENT and WRONG — malformed fields,
	// a signer that is not the key's fingerprint, a signature that does not
	// verify. Distinct from Proof==nil, and the distinction is the whole
	// downgrade defense: absent means "this domain does not sign", invalid
	// means "something tampered with a domain that does".
	ProofError string
}

// Resolver fetches and validates the effective manifest of a domain from the
// deterministic HTTPS authority. Implementations own domain normalization, URL
// construction, TLS validation, redirect refusal, transfer limits, canonical
// parsing and manifest validation — a caller cannot opt out of any of them.
type Resolver interface {
	// authority is a delegated authority DOMAIN already authorized by the
	// caller's trust state ("" = subject-domain bootstrap). Resolver validates
	// the returned object, but cannot decide whether a routing hint was allowed
	// to select this host; callers MUST NOT pass an untrusted first-contact a=.
	Resolve(ctx context.Context, domain, authority string) (Result, error)
}

// PeerState is the lifecycle position of a Peer.
type PeerState string

const (
	// StateDiscovered: an observation exists, no manifest has been accepted.
	StateDiscovered PeerState = "discovered"
	// StateActive: a valid effective manifest is available.
	StateActive PeerState = "active"
	// StateExpired: the effective manifest expired and no replacement arrived.
	StateExpired PeerState = "expired"
	// StateUnavailable: resolution failed and no usable manifest exists.
	StateUnavailable PeerState = "unavailable"
	// StateDisabled: an administrator disabled MKDP1 for this domain.
	StateDisabled PeerState = "disabled"
)

// Policy is the local administrative delivery policy for a domain.
type Policy string

const (
	// PolicyAuto encrypts when a valid manifest is available.
	PolicyAuto Policy = "auto"
	// PolicyRequire refuses plaintext: with no valid manifest, mail waits or
	// fails rather than being sent in the clear. Only an administrator — or a
	// successful HTTPS validation, never an observation — may arm this.
	PolicyRequire Policy = "require"
	// PolicyDisabled turns MKDP1 off for the domain entirely.
	PolicyDisabled Policy = "disabled"
)

// ObservationStatus is how an observation compares to the effective manifest.
type ObservationStatus string

const (
	ObservationPending      ObservationStatus = "pending"
	ObservationConfirmed    ObservationStatus = "confirmed"
	ObservationStale        ObservationStatus = "stale"
	ObservationMalformed    ObservationStatus = "malformed"
	ObservationInconsistent ObservationStatus = "inconsistent"
)

// Observation is one untrusted sighting of a domain's MKDP1 capability.
type Observation struct {
	Source     Source
	ManifestID ManifestID
	HasID      bool
	// Fingerprint is the identity fingerprint carried by a DNS sighting. HasFP
	// means every usable fingerprint-bearing record in that DNS answer agreed
	// on this value. It remains an observation: storing it must never install or
	// replace the identity pin.
	Fingerprint Fingerprint
	HasFP       bool
	// Authority is the delegated authority domain this sighting advertised
	// (a= — "" means self-hosted). It is retained for diagnostics and for use
	// after an identity pin exists; it never authorizes first-contact routing.
	Authority  string
	ObservedAt time.Time
	Status     ObservationStatus
	// Context is a privacy-minimized origin note (an internal message
	// reference, the resolver name) — never message content.
	Context string
}

// ManifestStatus is a stored manifest's role for its Peer.
type ManifestStatus string

const (
	ManifestEffective  ManifestStatus = "effective"
	ManifestHistorical ManifestStatus = "historical"
)

// ManifestRecord is a stored manifest: the immutable bytes, their identity and
// how they were obtained.
type ManifestRecord struct {
	ManifestID     ManifestID
	CanonicalBytes []byte
	Kid            KeyID
	IssuedAt       time.Time
	ExpiresAt      time.Time
	FetchedAt      time.Time
	AuthorityHost  string
	TLSVerified    bool
	Status         ManifestStatus
}

// Peer is the domain-level record: one per email domain, no matter how many
// sources observed it.
type Peer struct {
	Domain    string
	State     PeerState
	Policy    Policy
	Effective *ManifestRecord
	// History holds superseded manifests for diagnostics (the private keys
	// they name are retained separately, by the receiver).
	History        []ManifestRecord
	Observations   []Observation
	LastVerifiedAt time.Time
	NextRefreshAt  time.Time
	LastError      string
	// Issues is the bounded, coalesced review history: what has gone wrong with
	// this domain, how often, and when it last happened (spec 07 §12 P4).
	//
	// Separate from LastError, which holds only the most recent prose and is
	// therefore useless for review: it cannot say whether a condition happened
	// once or ten thousand times, and a later unrelated failure erases it.
	Issues []PeerIssue
	// AuthorityUnstable marks a domain whose authority alternates between
	// different valid manifests. MKDP1 refuses to invent a tie-break rule, so
	// this surfaces as a warning for a human instead.
	AuthorityUnstable bool

	// Identity is this sender's long-term trust state for the domain: the
	// pinned signing key, if any, and what has been observed about it.
	Identity IdentityState
}

/*
IdentityState is the sender half of the identity extension — what THIS sender
has decided to trust about a domain, kept across manifests, rotations and years.

Three facts are persisted independently because they answer different questions
and each is load-bearing on its own:

  - Pinned/Fingerprint: the trust anchor. Once set, a manifest signed by anything
    else is not a rotation, it is an alarm.
  - EverHTTPSValidated: downgrade protection. Set by ANY successful HTTPS
    retrieval, including an unsigned one and including a fetch after which
    pinning was withheld — so a domain that once answered over HTTPS may never
    silently fall back to plaintext during a later outage.
  - Status: whether long-term trust was withheld, and why. "Contested" is not a
    weaker pin; it is the deliberate refusal to create one while the evidence
    disagrees, and it must survive restarts or the next fetch would pin whatever
    it happened to see.

Merging any two of them loses something. In particular, a peer can be
EverHTTPSValidated (fail-closed on transport) while unpinned (no long-term
anchor) — which is exactly the state §6.2's contested row describes.
*/
type IdentityState struct {
	Status IdentityStatus
	// Fingerprint is the PINNED signing identity, set only when Status is
	// IdentityPinned.
	Fingerprint Fingerprint
	/*
		PinnedPublicKey is the pinned identity's Ed25519 public key — kept
		because a fingerprint alone cannot FOLLOW a rotation. A transition
		statement carries only the NEW key; its old_signature is verified
		against the key the verifier already trusts, and a verifier that stored
		only the hash of that key would be unable to check the very first link
		of any chain. Pins established before this field existed have it empty,
		and for them a signer change remains an operator decision.
	*/
	PinnedPublicKey []byte
	PinnedAt        time.Time
	// EverHTTPSValidated records that this domain has answered at least one
	// successful HTTPS authority fetch. It never returns to false.
	EverHTTPSValidated bool
	// DNSFingerprint is the fp last seen in DNS — an OBSERVATION. It can
	// corroborate a pin or contest one; it can never install or replace one.
	DNSFingerprint Fingerprint
	HasDNSFP       bool
	// DNSObservedAt records when DNSFingerprint was observed. The source is
	// deliberately implicit in the field: no other channel may populate it.
	DNSObservedAt time.Time
	// LastVerifiedIssuedAt and LastVerifiedManifestID are the replay defense
	// (§6.4): a signature proves authorization, not freshness, so an attacker
	// who can serve responses could otherwise return yesterday's still-valid
	// signed manifest forever.
	LastVerifiedIssuedAt   time.Time
	LastVerifiedManifestID ManifestID
	// Contested records why a pin was withheld or an alarm raised, for an
	// operator. Never used as an input to a decision.
	Contested string
}

// IdentityStatus is a domain's long-term trust position for this sender.
type IdentityStatus string

const (
	// IdentityUnpinned: no identity has been established. Legacy WebPKI
	// behaviour — this is where every relationship starts, and where an
	// unsigned domain stays.
	IdentityUnpinned IdentityStatus = "unpinned"
	// IdentityPinned: a signer is trusted for this domain. A manifest signed by
	// anything else is refused until an authorized rotation says otherwise.
	IdentityPinned IdentityStatus = "pinned"
	// IdentityContested: evidence disagreed, so pinning was WITHHELD. Mail is
	// still encrypted — to a WebPKI-authenticated key that an attacker may
	// hold — and the operator must be told exactly that.
	IdentityContested IdentityStatus = "contested"
)

/*
Capability is what this sender knows about a domain's TRANSPORT: that it has, at
least once, answered a successful HTTPS authority fetch.

It is deliberately NOT part of Peer, and that separation is the point rather than
tidiness. Peer holds cached manifests and observations — things a sender should
be able to discard freely, because discarding them costs one fetch. This costs
something entirely different: once a domain is known to speak MKDP1, sending it
plaintext because a refresh failed is a downgrade an attacker can cause on
demand, by letting a cached manifest expire and then disrupting the refresh.
01-PRD FR-7 and 04-SECURITY §7 forbid exactly that.

So the latch outlives the cache. "Forget this peer" means "drop what I cached,
rediscover it" and MUST leave this untouched. Only an explicit administrator
decision — recorded here as Disabled — may re-permit plaintext, because that
decision has a consequence no cache-hygiene operation should be able to carry
silently.

It is also independent of the identity extension. A domain that publishes no
signature at all still sets this on its first successful fetch: the claim is
about the transport, not about who signed anything.
*/
type Capability struct {
	// EverValidated never returns to false except through Disabled.
	EverValidated    bool
	FirstValidatedAt time.Time
	LastValidatedAt  time.Time
	// Disabled is the explicit administrator downgrade: stop requiring MKDP1 for
	// this domain. The ONLY thing that lifts the latch.
	Disabled   bool
	DisabledAt time.Time
	// Reason is the administrator's note for the downgrade, kept so the decision
	// is reviewable long after whoever made it has moved on.
	Reason string
}

// Requires reports whether this domain must not receive plaintext: it has been
// validated, and no administrator has decided otherwise.
func (c Capability) Requires() bool { return c.EverValidated && !c.Disabled }

// Store is the persistence seam. Implementations may use any database; the
// protocol requires only that InstallManifest is atomic.
type Store interface {
	// GetPeer returns the peer, or nil without error when unknown.
	GetPeer(ctx context.Context, domain string) (*Peer, error)
	// ListPeers enumerates every known peer.
	ListPeers(ctx context.Context) ([]Peer, error)
	// PutObservation appends (or coalesces) an observation, creating a
	// discovered peer when the domain is new.
	PutObservation(ctx context.Context, domain string, o Observation) error
	// InstallManifest atomically persists the fetched manifest, demotes the
	// previous effective manifest to historical, sets the new one effective,
	// reconciles observations against its id and updates peer status.
	InstallManifest(ctx context.Context, domain string, r Result) error
	// RecordFailure stores a resolution error without disturbing a manifest
	// that is still valid.
	RecordFailure(ctx context.Context, domain string, err error) error

	// RecordIssue folds one occurrence of a reviewable condition into the
	// peer's bounded issue history (see CoalesceIssue), and reports whether
	// this is its FIRST occurrence.
	//
	// That boolean is what keeps alerting sane: the same condition repeats on
	// every retry and every message, and an operator must hear about it once
	// per domain per condition. Returning it from the store rather than
	// computing it above is deliberate — only the store sees the read and the
	// write as one operation, so two concurrent sends cannot both conclude
	// they were first.
	RecordIssue(ctx context.Context, domain string, code IssueCode, detail string) (bool, error)

	// ClearIssue removes a condition that no longer holds, so a recurrence is
	// reported as news rather than folded into a months-old row.
	ClearIssue(ctx context.Context, domain string, code IssueCode) error
	// SetPolicy applies an administrative policy.
	SetPolicy(ctx context.Context, domain string, p Policy) error
	// ForgetPeer deletes cached manifests and observations. It is not a
	// blocklist: the domain may be rediscovered later.
	//
	// It MUST NOT clear the Capability latch. "Forget what I cached" and "stop
	// requiring encryption for this domain" are different decisions with
	// different consequences, and an implementation that folds the second into
	// the first hands an operator a downgrade every time they tidy up.
	ForgetPeer(ctx context.Context, domain string) error

	// SetIdentity persists a domain's long-term trust state — the pin and what
	// has been observed about it. Separate from InstallManifest because a
	// verdict is reached BEFORE a manifest is allowed to become cached state:
	// installing first would let a refused manifest be served from cache on the
	// next send, bypassing the decision entirely.
	//
	// Failure is security-significant, not advisory: the fetched manifest MUST
	// NOT be installed or returned for use unless this write succeeds.
	SetIdentity(ctx context.Context, domain string, state IdentityState) error

	// Capability reads the domain's transport latch. A domain never seen returns
	// the zero value, which requires nothing.
	Capability(ctx context.Context, domain string) (Capability, error)
	// ListCapabilities enumerates every domain carrying a latch, keyed by domain.
	//
	// Needed because a latch can outlive its peer record: Forget drops the cache
	// and the domain vanishes from ListPeers, while the requirement to encrypt
	// it survives — by design. Without this, an operator would be unable to see
	// or lift a requirement that is holding their mail, which turns the
	// protection into a trap.
	ListCapabilities(ctx context.Context) (map[string]Capability, error)
	// MarkValidated records a successful HTTPS authority fetch. Idempotent, and
	// called on EVERY success rather than only the first: the latch is set once,
	// but LastValidatedAt answers "when did this domain last actually work",
	// which is what an operator needs when deciding whether a refusal is an
	// attack or an outage.
	//
	// Failure MUST stop the fetched manifest from being installed or returned.
	// Otherwise a successful authority fetch followed by a storage fault can be
	// misread upstream as opportunistic "no key" and downgraded to plaintext.
	MarkValidated(ctx context.Context, domain string, at time.Time) error
	// SetMKDP1Disabled is the explicit administrator downgrade — the only
	// operation that lifts the latch. Separate from SetPolicy because policy
	// tightens and this loosens, and the two must not share a control.
	SetMKDP1Disabled(ctx context.Context, domain string, disabled bool, reason string, at time.Time) error
}

// Service is the protocol's application-facing behavior: observations in,
// validated keys out.
type Service interface {
	// ObserveDNS records TXT observations for a domain and schedules
	// resolution when they indicate the cache may be stale.
	ObserveDNS(ctx context.Context, domain string, txt []string) error
	// ObserveHeader records a Mail-Key header observation. It must never
	// block or fail inbound mail processing.
	ObserveHeader(ctx context.Context, headerValue, context string) error
	// AddPeer resolves a domain on an administrator's request.
	AddPeer(ctx context.Context, domain string) (Peer, error)
	// Refresh forces authority resolution for a known domain.
	Refresh(ctx context.Context, domain string) (Peer, error)
	// ResolveForEncryption returns a usable manifest for the outbound path:
	// the valid cached one when there is one, otherwise a fresh fetch. It
	// returns ErrNoKey when the domain has no usable key, which the caller
	// interprets according to the peer's policy.
	ResolveForEncryption(ctx context.Context, domain string) (Result, error)
	// ResolveAcceptingUnpinned is ResolveForEncryption for a sender who was
	// asked and said yes: a manifest refused ONLY because its signer is not the
	// pinned one is returned rather than withheld.
	//
	// It cannot produce cleartext. Where there is no key — the capability latch
	// — there is nothing for it to return, so "proceed means plaintext" is not
	// a case a caller has to remember to exclude. It also does not install what
	// it returns: the pin is unchanged and the next message asks again.
	ResolveAcceptingUnpinned(ctx context.Context, domain string) (Result, error)
	// Forget removes cached state for a domain.
	Forget(ctx context.Context, domain string) error
}

/*
IdentityChainResolver is the sender-side fetch of the §4.2 identity resource.

A separate, optional interface rather than a method on Resolver, because the two
fetches happen on different occasions and a Resolver that predates identity
signing remains complete: manifests resolve per send, the chain is fetched only
when a pinned domain's signer CHANGES — the one moment the history can answer a
question the manifest cannot.

The bytes come back raw and unparsed. Parsing and — above all — verification
belong to the caller walking the chain from its own pin: a resolver that
returned a parsed, "checked" document would be one refactor away from someone
trusting its check.
*/
type IdentityChainResolver interface {
	// authority is the same delegated authority DOMAIN already admitted by the
	// caller for the manifest fetch ("" = subject-domain route). The chain and
	// the manifest must be fetched through one routing decision; implementations
	// validate the returned resource but do not decide whether an observation
	// was trusted enough to select that route.
	ResolveIdentityChain(ctx context.Context, domain, authority string) ([]byte, error)
}

/*
IdentityPublisher is the OPTIONAL second half of publishing: the identity
resource of spec 07 §4.2, served beside the manifest endpoint.

Separate from Publisher because the two documents have opposite lifetimes — a
manifest is re-issued routinely, an identity document changes only on rotation —
and because a publisher without identity signing is a legitimate MKDP1 server
that must keep working unchanged. A handler type-asserts for this and serves 404
when it is absent, exactly as a server that never signed would.
*/
type IdentityPublisher interface {
	// CurrentIdentityDoc returns the canonical identity document for a hosted
	// domain — active key, status, rotation chain — or ok=false when the domain
	// publishes no identity.
	CurrentIdentityDoc(domain string) ([]byte, bool)
}

// KeyHandle is an opaque reference to a private key: raw bytes for a software
// key, or a handle an HSM understands. The library never inspects it.
type KeyHandle any

// PrivateKeyLookup resolves an inbound envelope's kid to the receiver's
// private key. Implementations MUST NOT rebind an existing kid to a different
// key descriptor — that is a critical integrity error, not an update.
type PrivateKeyLookup interface {
	FindPrivateKey(ctx context.Context, domain string, kid KeyID) (KeyHandle, error)
}

/*
Publication is ONE immutable publication snapshot: the manifest bytes, their id,
their validity, and the detached proof that authenticates exactly those bytes.

It is a single value rather than four returns because the spec requires the
handler to obtain one snapshot and serve all of its components together. A
publisher that looked up the manifest and the current identity independently
could pair a body from one build with a proof from another — and with detached
proofs that is not a subtle inconsistency, it is a verification failure at every
correspondent.

The same shape also removes a defect that exists with no signing at all: two
concurrent requests on a cold cache each building a manifest produce two
different manifest_ids for the same key at the same instant, which receivers are
entitled to read as an unstable authority. There is no way to express that bug
against a type that hands out the whole snapshot at once.
*/
type Publication struct {
	// Raw is served verbatim: it is what ID was computed over and what Proof
	// signed. Callers must not modify it.
	Raw       []byte
	ID        ManifestID
	ExpiresAt time.Time
	// Proof is nil for a domain that publishes a key but no identity — a valid
	// state, and the one every deployment starts in. Nil means "unsigned", never
	// "unverified".
	Proof *Proof
}

/*
Proof is the detached authentication of a Publication: the Ed25519 identity
public key, its fingerprint, and the signature over the manifest bytes.

Declared here rather than in the identity package because Publisher lives here
and the root package holds types only — the identity package owns every
operation that computes, signs or checks one.
*/
type Proof struct {
	PublicKey   []byte
	Fingerprint Fingerprint
	Signature   []byte
}

// Publisher is the receiving side of the protocol: it owns the current key and
// serves the canonical manifest bytes at the well-known endpoint.
type Publisher interface {
	// CurrentManifest returns the publication snapshot for a hosted domain, or
	// ok=false when the domain publishes no key.
	CurrentManifest(domain string) (pub Publication, ok bool)
}
