/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity

import (
	"crypto/ed25519"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"go.arpabet.com/value"
	"golang.org/x/xerrors"
)

/*
The identity resource (spec 07 §4.2, §5.2).

	GET https://mail.<d>/.well-known/mail-key-identity            head
	GET https://mail.<d>/.well-known/mail-key-identity/by-fp/<fp> one transition

Split from the manifest deliberately. Putting the chain in the manifest response
would make a long-lived object as chatty as a short-lived one; putting the
per-manifest signature here would make a long-lived object change on every
re-issue and destroy its cacheability. A client fetches this only to establish a
pin, to follow a rotation, or to check revocation — never per manifest refresh.

Old clients never request it, so it uses a STRICT schema: an unknown field is an
error rather than something to ignore. There is no deployed parser to stay
compatible with, and the one thing this resource must never do is let an
attacker smuggle a field past a verifier that shrugged at it.
*/

// ResourcePath is the head resource. ByFPPath is the prefix of the immutable
// per-transition objects, looked up by the fingerprint the transition INSTALLS.
const (
	ResourcePath = "/.well-known/mail-key-identity"
	ByFPPath     = ResourcePath + "/by-fp/"
)

// DocType tags the head document, so a body served under the wrong path or
// pasted from elsewhere cannot be read as something it is not.
const DocType = "mailkey-identity-doc-v1"

/*
Doc is the head resource: the identity a domain is signing with now, plus the
recent chain.

Status is the PUBLISHER's own word — "active", or "revoked" when the domain has
withdrawn its identity and has no successor. It is a convenience for operators
and dashboards and MUST NOT be trusted on its own: a verifier reaches its
conclusion by walking the signed chain from its pin, because status is just a
string the same server chose.
*/
type Doc struct {
	Type    string
	Version string
	Domain  string
	// Active is the identity currently in effect, with its fingerprint
	// recomputed by any reader rather than trusted from the wire.
	ActiveFP  mailkey.Fingerprint
	ActivePK  ed25519.PublicKey
	Alg       string
	Status    string
	UpdatedAt time.Time
	// Chain is the ordered transition history. Order is a courtesy to readers;
	// WalkChain does not depend on it, and must not, because the order is
	// chosen by whoever serves the document.
	Chain []Statement
}

const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

func packStatement(s Statement) value.Value {
	m := map[string]value.Value{
		"type":       value.Utf8(s.Type),
		"version":    value.Utf8(s.Version),
		"domain":     value.Utf8(s.Domain),
		"old_fp":     value.Raw(s.OldFP[:], false),
		"new_fp":     value.Raw(s.NewFP[:], false),
		"new_alg":    value.Utf8(s.NewAlg),
		"new_pk":     value.Raw(s.NewPK, false),
		"not_before": value.Long(s.NotBefore.Unix()),
		"created_at": value.Long(s.CreatedAt.Unix()),
		"expires_at": value.Long(s.ExpiresAt.Unix()),
		"reason":     value.Utf8(s.Reason),
	}
	if len(s.OldSignature) > 0 {
		m["old_signature"] = value.Raw(s.OldSignature, false)
	}
	if len(s.NewSignature) > 0 {
		m["new_signature"] = value.Raw(s.NewSignature, false)
	}
	return value.SortedMapOf(m)
}

/*
unpackStatement reads one chain entry under the STRICT schema: exactly the
expected fields, no more and no less.

Fail-closed on an unknown field is the whole reason this resource may use a new
schema — there is no deployed parser to stay compatible with, and the one thing
it must never do is let something be smuggled past a verifier that shrugged at
it. The signatures are optional as FIELDS (a revocation carries one, not two)
and are checked as SIGNATURES by VerifyStatement, where the rule about how many
are required lives.
*/
func unpackStatement(v value.Value) (Statement, error) {
	m, err := asMap(v, "identity statement")
	if err != nil {
		return Statement{}, err
	}
	for _, k := range m.Keys() {
		switch k {
		case "type", "version", "domain", "old_fp", "new_fp", "new_alg", "new_pk",
			"not_before", "created_at", "expires_at", "reason", "old_signature", "new_signature":
		default:
			return Statement{}, xerrors.Errorf("identity statement: unknown field %q", k)
		}
	}
	present := map[string]bool{}
	for _, k := range m.Keys() {
		present[k] = true
	}
	var s Statement
	if s.Type, err = utf8Field(m, "type"); err != nil {
		return Statement{}, err
	}
	if s.Version, err = utf8Field(m, "version"); err != nil {
		return Statement{}, err
	}
	if s.Domain, err = utf8Field(m, "domain"); err != nil {
		return Statement{}, err
	}
	if s.NewAlg, err = utf8Field(m, "new_alg"); err != nil {
		return Statement{}, err
	}
	if s.Reason, err = utf8Field(m, "reason"); err != nil {
		return Statement{}, err
	}
	oldFP, err := rawField(m, "old_fp")
	if err != nil {
		return Statement{}, err
	}
	newFP, err := rawField(m, "new_fp")
	if err != nil {
		return Statement{}, err
	}
	if len(oldFP) != len(s.OldFP) || len(newFP) != len(s.NewFP) {
		return Statement{}, xerrors.New("identity statement: a fingerprint is the wrong length")
	}
	copy(s.OldFP[:], oldFP)
	copy(s.NewFP[:], newFP)
	if s.NewPK, err = rawField(m, "new_pk"); err != nil {
		return Statement{}, err
	}
	// Presence is decided by KEY MEMBERSHIP, not by Get: the value API answers
	// an absent key with a non-nil null sentinel, and treating that as "present"
	// made every successorless revocation unparseable — the case §5.1 exists
	// for, silently unreachable.
	if present["old_signature"] {
		if s.OldSignature, err = rawField(m, "old_signature"); err != nil {
			return Statement{}, err
		}
	}
	if present["new_signature"] {
		if s.NewSignature, err = rawField(m, "new_signature"); err != nil {
			return Statement{}, err
		}
	}
	nb, err := longField(m, "not_before")
	if err != nil {
		return Statement{}, err
	}
	ca, err := longField(m, "created_at")
	if err != nil {
		return Statement{}, err
	}
	ea, err := longField(m, "expires_at")
	if err != nil {
		return Statement{}, err
	}
	s.NotBefore, s.CreatedAt, s.ExpiresAt = time.Unix(nb, 0).UTC(), time.Unix(ca, 0).UTC(), time.Unix(ea, 0).UTC()
	return s, nil
}

// PackDoc serializes the head resource canonically.
func PackDoc(d Doc) ([]byte, error) {
	dom, err := discovery.Normalize(d.Domain)
	if err != nil {
		return nil, xerrors.Errorf("identity resource: %w", err)
	}
	if len(d.Chain) > MaxChainEntries {
		return nil, xerrors.Errorf("%w: %d entries", ErrChainTooLong, len(d.Chain))
	}
	chain := value.EmptyList(false)
	for _, s := range d.Chain {
		chain = chain.Append(packStatement(s))
	}
	raw, err := value.Pack(value.SortedMapOf(map[string]value.Value{
		"type":       value.Utf8(DocType),
		"version":    value.Utf8(mailkey.Version),
		"domain":     value.Utf8(dom),
		"active_fp":  value.Raw(d.ActiveFP[:], false),
		"active_pk":  value.Raw(d.ActivePK, false),
		"alg":        value.Utf8(Alg),
		"status":     value.Utf8(d.Status),
		"updated_at": value.Long(d.UpdatedAt.Unix()),
		"chain":      chain,
	}))
	if err != nil {
		return nil, xerrors.Errorf("identity resource: %w", err)
	}
	return raw, nil
}

/*
ParseDoc reads a head resource.

The fingerprint is RECOMPUTED from the carried public key and the requested
domain — never taken from active_fp — for the same reason the detached proof
recomputes it: a server must not be able to name an identity it does not carry.
The domain comes from the CALLER, not the document, so a document lifted from
one domain's endpoint cannot authenticate for another.
*/
func ParseDoc(domain string, raw []byte) (Doc, error) {
	if len(raw) > MaxChainBytes {
		return Doc{}, xerrors.Errorf("identity resource: %d bytes, max %d", len(raw), MaxChainBytes)
	}
	dom, err := discovery.Normalize(domain)
	if err != nil {
		return Doc{}, xerrors.Errorf("identity resource: %w", err)
	}
	v, err := value.Unpack(raw, true)
	if err != nil {
		return Doc{}, xerrors.Errorf("identity resource: %w", err)
	}
	m, err := asMap(v, "identity resource")
	if err != nil {
		return Doc{}, err
	}
	if err := exactKeys(m, "identity resource",
		"type", "version", "domain", "active_fp", "active_pk", "alg", "status", "updated_at", "chain"); err != nil {
		return Doc{}, err
	}
	out := Doc{Domain: dom}
	if out.Type, err = utf8Field(m, "type"); err != nil {
		return Doc{}, err
	}
	if out.Type != DocType {
		return Doc{}, xerrors.Errorf("identity resource: type %q, want %q", out.Type, DocType)
	}
	if out.Version, err = utf8Field(m, "version"); err != nil {
		return Doc{}, err
	}
	if out.Version != mailkey.Version {
		return Doc{}, xerrors.Errorf("identity resource: version %q, want %q", out.Version, mailkey.Version)
	}
	docDomain, err := utf8Field(m, "domain")
	if err != nil {
		return Doc{}, err
	}
	if docDomain != dom {
		// The domain comes from the CALLER. A document lifted from one domain's
		// endpoint must not authenticate for another.
		return Doc{}, xerrors.New("identity resource: the document names a different domain than the one fetched")
	}
	if out.Alg, err = utf8Field(m, "alg"); err != nil {
		return Doc{}, err
	}
	if out.Alg != Alg {
		return Doc{}, xerrors.Errorf("identity resource: alg %q, want %q", out.Alg, Alg)
	}
	if out.Status, err = utf8Field(m, "status"); err != nil {
		return Doc{}, err
	}
	upd, err := longField(m, "updated_at")
	if err != nil {
		return Doc{}, err
	}
	out.UpdatedAt = time.Unix(upd, 0).UTC()
	if out.ActivePK, err = rawField(m, "active_pk"); err != nil {
		return Doc{}, err
	}
	if len(out.ActivePK) != ed25519.PublicKeySize {
		return Doc{}, xerrors.Errorf("identity resource: active_pk is %d bytes, want %d", len(out.ActivePK), ed25519.PublicKeySize)
	}
	want, err := FingerprintOf(dom, out.ActivePK)
	if err != nil {
		return Doc{}, err
	}
	claimed, err := rawField(m, "active_fp")
	if err != nil {
		return Doc{}, err
	}
	var got mailkey.Fingerprint
	if len(claimed) != len(got) {
		return Doc{}, xerrors.New("identity resource: active_fp is the wrong length")
	}
	copy(got[:], claimed)
	if got != want {
		return Doc{}, xerrors.New("identity resource: active_fp does not match active_pk — the document names an identity it does not carry")
	}
	out.ActiveFP = want

	if lst, ok := m.Get("chain").(value.List); ok {
		entries := lst.Values()
		if len(entries) > MaxChainEntries {
			return Doc{}, xerrors.Errorf("%w: %d entries", ErrChainTooLong, len(entries))
		}
		for _, e := range entries {
			s, serr := unpackStatement(e)
			if serr != nil {
				return Doc{}, serr
			}
			out.Chain = append(out.Chain, s)
		}
	}
	return out, nil
}

// ByFPPathFor is the immutable object's path for the fingerprint a transition
// installs. Fingerprints are content-addressed, so the object at this path can
// be cached with a long max-age and `immutable`: it can never legitimately
// change, because a different transition would install a different fingerprint.
func ByFPPathFor(fp mailkey.Fingerprint) string {
	return ByFPPath + encodeB64(fp[:])
}

/*
Strict field accessors.

Duplicated from the manifest package rather than exported from it: they are four
lines each, and exporting a parser's internals so a second parser can share them
is how two schemas quietly become one. The manifest's rules are fixed by a
deployed wire format; this resource's are free to be stricter, and that freedom
only survives if the two do not share a definition of "a field".
*/
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

// exactKeys fails closed on anything unrecognised: no unknown fields, none
// missing.
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
		return "", xerrors.Errorf("identity resource: field %q must be a UTF-8 string", key)
	}
	return s.Utf8(), nil
}

func rawField(m value.Map, key string) ([]byte, error) {
	v := m.Get(key)
	s, ok := v.(value.String)
	if !ok || v.Kind() != value.STRING || s.Type() != value.RAW {
		return nil, xerrors.Errorf("identity resource: field %q must be raw bytes", key)
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
		return 0, xerrors.Errorf("identity resource: field %q must be a 64-bit integer", key)
	}
	return n.Long(), nil
}

/*
PackChain and ParseChain serialize a statement list on its own — the publisher's
STORAGE form, distinct from the served document.

The distinction matters because the two have different lifetimes: the document
carries the active key and is rebuilt on every change, while the stored chain is
append-only history that must survive every rotation including the one being
made. Statements round-trip byte-identically — their signatures cover fields
this encoding must not reinterpret — which ParseChain re-checks structurally by
reusing the strict statement schema.
*/
func PackChain(chain []Statement) ([]byte, error) {
	if len(chain) > MaxChainEntries {
		return nil, xerrors.Errorf("%w: %d entries", ErrChainTooLong, len(chain))
	}
	lst := value.EmptyList(false)
	for _, s := range chain {
		lst = lst.Append(packStatement(s))
	}
	return value.Pack(lst)
}

func ParseChain(raw []byte) ([]Statement, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > MaxChainBytes {
		return nil, xerrors.Errorf("identity chain: %d bytes, max %d", len(raw), MaxChainBytes)
	}
	v, err := value.Unpack(raw, true)
	if err != nil {
		return nil, xerrors.Errorf("identity chain: %w", err)
	}
	lst, ok := v.(value.List)
	if !ok {
		return nil, xerrors.New("identity chain: body is not a list")
	}
	entries := lst.Values()
	if len(entries) > MaxChainEntries {
		return nil, xerrors.Errorf("%w: %d entries", ErrChainTooLong, len(entries))
	}
	var out []Statement
	for _, e := range entries {
		s, serr := unpackStatement(e)
		if serr != nil {
			return nil, serr
		}
		out = append(out, s)
	}
	return out, nil
}
