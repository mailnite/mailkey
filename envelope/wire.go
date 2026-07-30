/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package envelope

import (
	"encoding/base64"

	"github.com/mailnite/mailkey"
	"go.arpabet.com/value"
	"golang.org/x/xerrors"
)

// MaxWireBytes bounds an envelope read off the wire before it is parsed. Mail
// bodies are large, so this is generous — but it is finite, and it is checked
// before allocation.
const MaxWireBytes = 64 << 20

// Marshal renders an envelope as canonical MessagePack. The header fields are
// written individually rather than as a nested blob so a reader can inspect
// kid and domain cheaply — the authentication of those fields comes from the
// AEAD tag, not from the framing.
func (e *Envelope) Marshal() ([]byte, error) {
	if err := e.Header.Validate(); err != nil {
		return nil, err
	}
	if len(e.Nonce) != nonceLen {
		return nil, xerrors.Errorf("envelope: nonce must be %d bytes, got %d", nonceLen, len(e.Nonce))
	}
	h := e.Header
	return value.Pack(value.SortedMapOf(map[string]value.Value{
		"v":            value.Long(int64(h.Version)),
		"suite":        value.Utf8(h.Suite),
		"domain":       value.Utf8(h.Domain),
		"kid":          value.Raw(h.Kid[:], true),
		"manifest_id":  value.Raw(h.ManifestID[:], true),
		"alg":          value.Utf8(h.Algorithm),
		"enc":          value.Utf8(h.Encryption),
		"ephemeral_pk": value.Raw(h.EphemeralPub, true),
		"nonce":        value.Raw(e.Nonce, true),
		"ciphertext":   value.Raw(e.Ciphertext, true),
	}))
}

// Unmarshal parses an envelope. It validates structure and types only: the
// contents are not trusted until Open authenticates them, so this stage exists
// to fail fast and safely on garbage, never to decide anything.
func Unmarshal(raw []byte) (*Envelope, error) {
	if len(raw) == 0 {
		return nil, xerrors.New("envelope: empty")
	}
	if len(raw) > MaxWireBytes {
		return nil, xerrors.Errorf("envelope: %d bytes exceeds the %d byte limit", len(raw), MaxWireBytes)
	}
	val, err := value.Unpack(raw, true)
	if err != nil {
		return nil, xerrors.Errorf("envelope: unpack: %w", err)
	}
	m, ok := val.(value.Map)
	if !ok || val.Kind() != value.MAP {
		return nil, xerrors.New("envelope: expected a map")
	}
	ver, err := longAt(m, "v")
	if err != nil {
		return nil, err
	}
	suite, err := utf8At(m, "suite")
	if err != nil {
		return nil, err
	}
	domain, err := utf8At(m, "domain")
	if err != nil {
		return nil, err
	}
	alg, err := utf8At(m, "alg")
	if err != nil {
		return nil, err
	}
	enc, err := utf8At(m, "enc")
	if err != nil {
		return nil, err
	}
	kid, err := idAt(m, "kid")
	if err != nil {
		return nil, err
	}
	mid, err := idAt(m, "manifest_id")
	if err != nil {
		return nil, err
	}
	ephemeral, err := rawAt(m, "ephemeral_pk")
	if err != nil {
		return nil, err
	}
	nonce, err := rawAt(m, "nonce")
	if err != nil {
		return nil, err
	}
	ciphertext, err := rawAt(m, "ciphertext")
	if err != nil {
		return nil, err
	}
	e := &Envelope{
		Header: Header{
			Version:      uint32(ver),
			Suite:        suite,
			Domain:       domain,
			Kid:          mailkey.KeyID(kid),
			ManifestID:   mailkey.ManifestID(mid),
			Algorithm:    alg,
			Encryption:   enc,
			EphemeralPub: ephemeral,
		},
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	if err := e.Header.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// MarshalBase64 encodes an envelope for carriage in a message body.
func (e *Envelope) MarshalBase64() (string, error) {
	b, err := e.Marshal()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// UnmarshalBase64 parses an envelope from a message body.
func UnmarshalBase64(s string) (*Envelope, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, xerrors.Errorf("envelope: base64: %w", err)
	}
	return Unmarshal(b)
}

func utf8At(m value.Map, key string) (string, error) {
	v := m.Get(key)
	s, ok := v.(value.String)
	if !ok || v.Kind() != value.STRING || s.Type() != value.UTF8 {
		return "", xerrors.Errorf("envelope: field %q must be a UTF-8 string", key)
	}
	return s.Utf8(), nil
}

func rawAt(m value.Map, key string) ([]byte, error) {
	v := m.Get(key)
	s, ok := v.(value.String)
	if !ok || v.Kind() != value.STRING || s.Type() != value.RAW {
		return nil, xerrors.Errorf("envelope: field %q must be raw bytes", key)
	}
	b := s.Raw()
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func longAt(m value.Map, key string) (int64, error) {
	v := m.Get(key)
	n, ok := v.(value.Number)
	if !ok || v.Kind() != value.NUMBER || n.Type() != value.LONG {
		return 0, xerrors.Errorf("envelope: field %q must be a 64-bit integer", key)
	}
	return n.Long(), nil
}

func idAt(m value.Map, key string) ([32]byte, error) {
	var out [32]byte
	b, err := rawAt(m, key)
	if err != nil {
		return out, err
	}
	if len(b) != len(out) {
		return out, xerrors.Errorf("envelope: field %q must be %d bytes, got %d", key, len(out), len(b))
	}
	copy(out[:], b)
	return out, nil
}
