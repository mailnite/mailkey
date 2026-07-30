/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package manifest is the normative MKDP1 wire format: the canonical
serialization of a manifest, and the two identifiers derived from it.

Everything here is deterministic and dependency-light on purpose — a second
implementation must be able to reproduce these bytes exactly. The canonical
form is the MessagePack stream produced by go.arpabet.com/value: string map
keys sorted bytewise, integers in their smallest encoding, UTF-8 strings and
raw bytes as distinct types. JSON is diagnostic only and is never hashed.

Two identifiers, two jobs:

	kid         = SHA-256(pack(domain, alg, enc, pk))  — names the KEY
	manifest_id = SHA-256(canonical manifest bytes)     — names the FETCH

kid is what the receiver looks a private key up by, so it must not depend on
timestamps; manifest_id covers the whole object including validity, so any
field change gives a new id. Neither is ever compared for ordering.
*/
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/mailnite/mailkey"
	"go.arpabet.com/value"
	"golang.org/x/xerrors"
)

// Field names of the manifest map. They are part of the wire format.
const (
	fieldVersion   = "v"
	fieldDomain    = "domain"
	fieldIssuedAt  = "issued_at"
	fieldExpiresAt = "expires_at"
	fieldKey       = "key"

	fieldKid = "kid"
	fieldAlg = "alg"
	fieldEnc = "enc"
	fieldPk  = "pk"
)

// keyDescriptorType is the domain-separation tag in the kid preimage. It keeps
// a kid from colliding with any other hash this protocol computes, and pins the
// preimage layout: a future layout takes a new tag.
const keyDescriptorType = "mailkey-envelope-key-v1"

const keyDescriptorTypeField = "type"

// pubKeyLenX25519 is the exact public-key length for alg=x25519.
const pubKeyLenX25519 = 32

// Limits bound what a manifest may claim. They are validation policy, not wire
// format: two implementations may differ here and still interoperate.
type Limits struct {
	// MaxLifetime is the longest validity interval a manifest may declare.
	MaxLifetime time.Duration
	// MaxClockSkew is how far into the future issued_at may sit.
	MaxClockSkew time.Duration
}

// DefaultLimits are the recommended bounds: a manifest may not claim more than
// 30 days of validity, and may not be issued more than 5 minutes ahead of us.
func DefaultLimits() Limits {
	return Limits{MaxLifetime: 30 * 24 * time.Hour, MaxClockSkew: 5 * time.Minute}
}

// KeyIDOf computes kid over a key descriptor. The domain and both algorithm
// identifiers are inside the preimage, so the same public key published for a
// different domain — or under a different suite — is a different kid. That is
// what prevents cross-domain and cross-suite substitution.
//
// The caller passes an already-normalized domain; this function does not
// normalize, so that a receiver computing kid at key-generation time and a
// sender computing it at discovery time cannot disagree about normalization.
func KeyIDOf(domain, alg, enc string, publicKey []byte) (mailkey.KeyID, error) {
	var kid mailkey.KeyID
	if domain == "" {
		return kid, xerrors.New("key id: empty domain")
	}
	if err := checkSuite(alg, enc, publicKey); err != nil {
		return kid, err
	}
	raw, err := value.Pack(value.SortedMapOf(map[string]value.Value{
		keyDescriptorTypeField: value.Utf8(keyDescriptorType),
		fieldDomain:            value.Utf8(domain),
		fieldAlg:               value.Utf8(alg),
		fieldEnc:               value.Utf8(enc),
		fieldPk:                value.Raw(publicKey, true),
	}))
	if err != nil {
		return kid, xerrors.Errorf("key id: pack: %w", err)
	}
	return sha256.Sum256(raw), nil
}

// checkSuite validates the algorithm pair and the public-key length for it.
// Unknown identifiers fail closed: a client must never guess how to encrypt.
func checkSuite(alg, enc string, publicKey []byte) error {
	if alg != mailkey.AlgX25519 {
		return xerrors.Errorf("unsupported algorithm %q", alg)
	}
	if enc != mailkey.EncAES256GCM {
		return xerrors.Errorf("unsupported encryption %q", enc)
	}
	if len(publicKey) != pubKeyLenX25519 {
		return xerrors.Errorf("%s public key must be %d bytes, got %d", alg, pubKeyLenX25519, len(publicKey))
	}
	return nil
}

// New builds a manifest for a domain's key, computing its kid. domain must
// already be normalized (see the discovery package).
func New(domain string, issuedAt, expiresAt time.Time, alg, enc string, publicKey []byte) (mailkey.Manifest, error) {
	kid, err := KeyIDOf(domain, alg, enc, publicKey)
	if err != nil {
		return mailkey.Manifest{}, err
	}
	pk := make([]byte, len(publicKey))
	copy(pk, publicKey)
	return mailkey.Manifest{
		Version:   mailkey.Version,
		Domain:    domain,
		IssuedAt:  issuedAt.UTC().Truncate(time.Second),
		ExpiresAt: expiresAt.UTC().Truncate(time.Second),
		Key: mailkey.KeyDescriptor{
			Kid: kid, Algorithm: alg, Encryption: enc, PublicKey: pk,
		},
	}, nil
}

// Pack renders a manifest as its canonical bytes. Field order is irrelevant to
// the output: the canonical form sorts map keys, so the same logical manifest
// always packs to the same bytes.
func Pack(m mailkey.Manifest) ([]byte, error) {
	if m.Version != mailkey.Version {
		return nil, xerrors.Errorf("pack: unsupported version %q", m.Version)
	}
	if m.Domain == "" {
		return nil, xerrors.New("pack: empty domain")
	}
	if err := checkSuite(m.Key.Algorithm, m.Key.Encryption, m.Key.PublicKey); err != nil {
		return nil, xerrors.Errorf("pack: %w", err)
	}
	// The kid inside the object must be the kid OF the object: packing a
	// manifest whose kid does not match its own key would publish bytes no
	// validating client could accept.
	kid, err := KeyIDOf(m.Domain, m.Key.Algorithm, m.Key.Encryption, m.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	if kid != m.Key.Kid {
		return nil, xerrors.New("pack: kid does not match the key descriptor")
	}
	keyMap := value.SortedMapOf(map[string]value.Value{
		fieldKid: value.Raw(kid[:], true),
		fieldAlg: value.Utf8(m.Key.Algorithm),
		fieldEnc: value.Utf8(m.Key.Encryption),
		fieldPk:  value.Raw(m.Key.PublicKey, true),
	})
	return value.Pack(value.SortedMapOf(map[string]value.Value{
		fieldVersion:   value.Utf8(m.Version),
		fieldDomain:    value.Utf8(m.Domain),
		fieldIssuedAt:  value.Long(m.IssuedAt.Unix()),
		fieldExpiresAt: value.Long(m.ExpiresAt.Unix()),
		fieldKey:       keyMap,
	}))
}

// ManifestIDOf is SHA-256 of canonical manifest bytes. Call it on the bytes
// that were RECEIVED (or packed once and kept), never on a re-serialization.
func ManifestIDOf(canonical []byte) mailkey.ManifestID {
	return sha256.Sum256(canonical)
}

// ParseCanonical decodes, validates and re-canonicalizes a manifest received
// from an authority. requestedDomain is the domain the caller asked for: a
// manifest that describes a different domain is refused, so a compromised host
// cannot answer for its neighbours.
//
// The final step is the important one — the decoded object is repacked and the
// bytes must be byte-identical to the input. That single check enforces the
// whole canonical form (key order, integer widths, string vs. binary types)
// and rejects trailing garbage, without trusting the parser's own strictness
// or mutating the host application's global decode limits.
func ParseCanonical(raw []byte, requestedDomain string) (mailkey.Manifest, error) {
	var zero mailkey.Manifest
	if len(raw) == 0 {
		return zero, xerrors.New("manifest: empty body")
	}
	if len(raw) > mailkey.MaxBodyBytes {
		return zero, xerrors.Errorf("manifest: body of %d bytes exceeds the %d byte limit", len(raw), mailkey.MaxBodyBytes)
	}
	val, err := value.Unpack(raw, true)
	if err != nil {
		return zero, xerrors.Errorf("manifest: unpack: %w", err)
	}
	top, err := asMap(val, "manifest")
	if err != nil {
		return zero, err
	}
	if err := exactKeys(top, "manifest", fieldVersion, fieldDomain, fieldIssuedAt, fieldExpiresAt, fieldKey); err != nil {
		return zero, err
	}
	ver, err := utf8Field(top, fieldVersion)
	if err != nil {
		return zero, err
	}
	if ver != mailkey.Version {
		return zero, xerrors.Errorf("manifest: unsupported version %q", ver)
	}
	domain, err := utf8Field(top, fieldDomain)
	if err != nil {
		return zero, err
	}
	if requestedDomain != "" && domain != requestedDomain {
		return zero, xerrors.Errorf("manifest: describes domain %q, requested %q", domain, requestedDomain)
	}
	issued, err := longField(top, fieldIssuedAt)
	if err != nil {
		return zero, err
	}
	expires, err := longField(top, fieldExpiresAt)
	if err != nil {
		return zero, err
	}
	keyVal, err := asMap(top.Get(fieldKey), "manifest key")
	if err != nil {
		return zero, err
	}
	if err := exactKeys(keyVal, "manifest key", fieldKid, fieldAlg, fieldEnc, fieldPk); err != nil {
		return zero, err
	}
	alg, err := utf8Field(keyVal, fieldAlg)
	if err != nil {
		return zero, err
	}
	enc, err := utf8Field(keyVal, fieldEnc)
	if err != nil {
		return zero, err
	}
	pk, err := rawField(keyVal, fieldPk)
	if err != nil {
		return zero, err
	}
	kidBytes, err := rawField(keyVal, fieldKid)
	if err != nil {
		return zero, err
	}
	if len(kidBytes) != len(mailkey.KeyID{}) {
		return zero, xerrors.Errorf("manifest: kid must be %d bytes, got %d", len(mailkey.KeyID{}), len(kidBytes))
	}
	if err := checkSuite(alg, enc, pk); err != nil {
		return zero, xerrors.Errorf("manifest: %w", err)
	}
	want, err := KeyIDOf(domain, alg, enc, pk)
	if err != nil {
		return zero, xerrors.Errorf("manifest: %w", err)
	}
	var got mailkey.KeyID
	copy(got[:], kidBytes)
	if got != want {
		return zero, xerrors.New("manifest: kid does not match the published key")
	}
	m := mailkey.Manifest{
		Version:   ver,
		Domain:    domain,
		IssuedAt:  time.Unix(issued, 0).UTC(),
		ExpiresAt: time.Unix(expires, 0).UTC(),
		Key:       mailkey.KeyDescriptor{Kid: want, Algorithm: alg, Encryption: enc, PublicKey: pk},
	}
	// Canonical round trip: the bytes we would produce must be the bytes we
	// were given, exactly.
	repacked, err := Pack(m)
	if err != nil {
		return zero, xerrors.Errorf("manifest: repack: %w", err)
	}
	if !bytes.Equal(repacked, raw) {
		return zero, xerrors.New("manifest: response is not canonical MKDP1 MessagePack")
	}
	return m, nil
}

// Validate applies time and lifetime policy to a parsed manifest.
func Validate(m mailkey.Manifest, now time.Time, limits Limits) error {
	if !m.ExpiresAt.After(m.IssuedAt) {
		return xerrors.New("manifest: expires_at must be later than issued_at")
	}
	if limits.MaxLifetime > 0 && m.ExpiresAt.Sub(m.IssuedAt) > limits.MaxLifetime {
		return xerrors.Errorf("manifest: validity of %s exceeds the %s maximum",
			m.ExpiresAt.Sub(m.IssuedAt), limits.MaxLifetime)
	}
	if m.IssuedAt.After(now.Add(limits.MaxClockSkew)) {
		return xerrors.Errorf("manifest: issued_at %s is in the future", m.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !m.ExpiresAt.After(now) {
		return xerrors.Errorf("manifest: expired at %s", m.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return nil
}

// --- text encodings of the identifiers ---------------------------------------

// EncodeID renders an identifier for text protocols and UIs: unpadded
// base64url. The full value is always encoded — identifiers are never
// truncated on the wire.
func EncodeID(id [32]byte) string { return base64.RawURLEncoding.EncodeToString(id[:]) }

// DecodeID parses an unpadded base64url identifier. Padding, wrong length and
// non-base64url alphabets are all refused.
func DecodeID(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return out, xerrors.Errorf("identifier: %w", err)
	}
	if len(b) != len(out) {
		return out, xerrors.Errorf("identifier: must be %d bytes, got %d", len(out), len(b))
	}
	copy(out[:], b)
	return out, nil
}

// --- typed field access ------------------------------------------------------
//
// Each accessor pins BOTH the presence and the exact value kind. MKDP1 has no
// type coercion: a UTF-8 string where raw bytes are required is an error, not
// something to convert, because the two encode differently and the canonical
// comparison would fail anyway — failing here just says why.

func asMap(v value.Value, what string) (value.Map, error) {
	if v == nil || v.Kind() != value.MAP {
		return nil, xerrors.Errorf("%s: expected a map", what)
	}
	m, ok := v.(value.Map)
	if !ok {
		return nil, xerrors.Errorf("%s: expected a map", what)
	}
	return m, nil
}

// exactKeys requires the map to carry exactly the named keys — no unknown
// fields (fail closed on anything we do not understand), none missing.
func exactKeys(m value.Map, what string, want ...string) error {
	keys := m.Keys()
	if len(keys) != len(want) {
		return xerrors.Errorf("%s: expected %d fields, got %d", what, len(want), len(keys))
	}
	for _, k := range want {
		if m.Get(k) == nil {
			return xerrors.Errorf("%s: missing field %q", what, k)
		}
	}
	return nil
}

func utf8Field(m value.Map, key string) (string, error) {
	v := m.Get(key)
	s, ok := v.(value.String)
	if !ok || v.Kind() != value.STRING || s.Type() != value.UTF8 {
		return "", xerrors.Errorf("manifest: field %q must be a UTF-8 string", key)
	}
	return s.Utf8(), nil
}

func rawField(m value.Map, key string) ([]byte, error) {
	v := m.Get(key)
	s, ok := v.(value.String)
	if !ok || v.Kind() != value.STRING || s.Type() != value.RAW {
		return nil, xerrors.Errorf("manifest: field %q must be raw bytes", key)
	}
	b := s.Raw()
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func longField(m value.Map, key string) (int64, error) {
	v := m.Get(key)
	n, ok := v.(value.Number)
	if !ok || v.Kind() != value.NUMBER || n.Type() != value.LONG {
		return 0, xerrors.Errorf("manifest: field %q must be a 64-bit integer", key)
	}
	return n.Long(), nil
}
