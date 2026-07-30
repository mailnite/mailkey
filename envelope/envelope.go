/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package envelope is the MKDP1 sealed message: the container a sender produces
once it holds a validated manifest, and the receiver opens with the private key
named by kid.

The construction, named by SuiteX25519HKDFSHA256AES256GCM:

	ephemeral X25519 key pair per message
	shared   = ECDH(ephemeral private, recipient public)
	key      = HKDF-SHA256(secret: shared, salt: ephemeralPub || recipientPub,
	                       info: "mailkey/mkdp1/x25519-aes256gcm/v1", len: 32)
	ciphertext = AES-256-GCM(key, nonce: 12 random bytes, plaintext, aad: header)
	aad      = canonical value.Pack of the header map below

The last line is the part that matters, and the reason this is a NEW suite
rather than a tweak of Mailnite's original envelope. MKDP1 puts identifiers in
the envelope — recipient domain, kid, manifest id, algorithm names — and those
identifiers are exactly what an on-path attacker would want to rewrite: point
kid at a different retained key and delivery silently fails; rewrite the domain
or the manifest id and the receiver's own audit record of how the message was
encrypted becomes attacker-authored. Binding them as AEAD associated data makes
any such edit a decryption failure instead. See SECURITY-REVIEW.md, finding F-1.

Nothing here is secret except the plaintext: the header travels in the clear so
the receiver can route the key lookup before it can decrypt anything. AEAD
authenticates it; it does not hide it.
*/
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"go.arpabet.com/value"
	"golang.org/x/xerrors"
)

// SuiteX25519HKDFSHA256AES256GCM is the identifier of this construction. A
// change to ANY step — derivation, nonce, associated data, cipher — takes a new
// suite identifier, so two implementations can never silently disagree about
// how bytes were produced.
const SuiteX25519HKDFSHA256AES256GCM = "mkdp1-x25519-hkdf-sha256-aes256gcm"

// Version is the envelope schema version.
const Version = 1

const (
	pubKeyLen  = 32
	nonceLen   = 12
	aeadKeyLen = 32
)

// hkdfInfo separates this construction's key schedule from every other use of
// the same ECDH secret.
const hkdfInfo = "mailkey/mkdp1/x25519-aes256gcm/v1"

// Header is the authenticated, cleartext part of an envelope: who it is for,
// which key opens it, and which discovery result produced it. Every field is
// covered by the AEAD tag.
type Header struct {
	Version uint32
	Suite   string
	// Domain is the normalized recipient domain the message was sealed for.
	Domain string
	// Kid names the recipient private key — a direct lookup, never a trial
	// walk over every retained key.
	Kid mailkey.KeyID
	// ManifestID records the exact discovery manifest the sender used, so the
	// receiver can audit how a message came to be encrypted the way it was.
	ManifestID mailkey.ManifestID
	Algorithm  string
	Encryption string
	// EphemeralPub is the sender's per-message public key: the encapsulation
	// data this suite needs, authenticated like everything else.
	EphemeralPub []byte
}

// Envelope is a sealed message: an authenticated header, the nonce, and the
// ciphertext.
type Envelope struct {
	Header     Header
	Nonce      []byte
	Ciphertext []byte
}

// Seal encrypts plaintext to a validated manifest result. The caller passes the
// Result it got from the resolver, so the envelope's identifiers cannot drift
// from the manifest that authorized the key.
func Seal(r mailkey.Result, plaintext []byte) (*Envelope, error) {
	m := r.Manifest
	if m.Domain == "" {
		return nil, xerrors.New("seal: manifest has no domain")
	}
	if m.Key.Algorithm != mailkey.AlgX25519 || m.Key.Encryption != mailkey.EncAES256GCM {
		return nil, xerrors.Errorf("seal: unsupported suite %s/%s", m.Key.Algorithm, m.Key.Encryption)
	}
	if len(m.Key.PublicKey) != pubKeyLen {
		return nil, xerrors.Errorf("seal: public key must be %d bytes, got %d", pubKeyLen, len(m.Key.PublicKey))
	}
	pub, err := ecdh.X25519().NewPublicKey(m.Key.PublicKey)
	if err != nil {
		return nil, xerrors.Errorf("seal: invalid recipient public key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	hdr := Header{
		Version:      Version,
		Suite:        SuiteX25519HKDFSHA256AES256GCM,
		Domain:       m.Domain,
		Kid:          m.Key.Kid,
		ManifestID:   r.ManifestID,
		Algorithm:    m.Key.Algorithm,
		Encryption:   m.Key.Encryption,
		EphemeralPub: eph.PublicKey().Bytes(),
	}
	aad, err := hdr.AAD()
	if err != nil {
		return nil, err
	}
	aead, err := deriveAEAD(shared, hdr.EphemeralPub, m.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Envelope{
		Header:     hdr,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, aad),
	}, nil
}

// Open decrypts an envelope with the recipient's private key. It fails if the
// key is wrong, the ciphertext was altered, or ANY header field was altered —
// the three are indistinguishable to a caller by design, so a failure never
// tells an attacker which of their edits was noticed.
func Open(recipientPriv []byte, e *Envelope) ([]byte, error) {
	if e == nil {
		return nil, xerrors.New("open: nil envelope")
	}
	if err := e.Header.Validate(); err != nil {
		return nil, err
	}
	if len(recipientPriv) != pubKeyLen {
		return nil, xerrors.Errorf("open: private key must be %d bytes, got %d", pubKeyLen, len(recipientPriv))
	}
	if len(e.Nonce) != nonceLen {
		return nil, xerrors.Errorf("open: nonce must be %d bytes, got %d", nonceLen, len(e.Nonce))
	}
	priv, err := ecdh.X25519().NewPrivateKey(recipientPriv)
	if err != nil {
		return nil, xerrors.Errorf("open: invalid private key: %w", err)
	}
	eph, err := ecdh.X25519().NewPublicKey(e.Header.EphemeralPub)
	if err != nil {
		return nil, xerrors.Errorf("open: invalid ephemeral public key: %w", err)
	}
	// The private key must be the one the header names. Checking it here turns
	// "someone handed us the wrong key" into a clear error instead of an
	// authentication failure that looks like tampering.
	kid, err := KeyIDOfPrivate(e.Header.Domain, e.Header.Algorithm, e.Header.Encryption, priv)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(kid[:], e.Header.Kid[:]) != 1 {
		return nil, xerrors.New("open: private key does not match the envelope's kid")
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	aad, err := e.Header.AAD()
	if err != nil {
		return nil, err
	}
	aead, err := deriveAEAD(shared, e.Header.EphemeralPub, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, e.Nonce, e.Ciphertext, aad)
	if err != nil {
		return nil, xerrors.New("open: authentication failed (wrong key, or the message or its metadata was altered)")
	}
	return plaintext, nil
}

// KeyIDOfPrivate computes the kid of a private key's public half — how a
// receiver indexes its own keys, and how Open checks it was handed the right
// one. It delegates to manifest.KeyIDOf: the preimage must have exactly ONE
// implementation, or a change to it would make senders and receivers compute
// different identifiers for the same key.
func KeyIDOfPrivate(domain, alg, enc string, priv *ecdh.PrivateKey) (mailkey.KeyID, error) {
	return manifest.KeyIDOf(domain, alg, enc, priv.PublicKey().Bytes())
}

// Validate checks a header's self-consistency before any crypto runs.
func (h Header) Validate() error {
	if h.Version != Version {
		return xerrors.Errorf("envelope: unsupported version %d", h.Version)
	}
	if h.Suite != SuiteX25519HKDFSHA256AES256GCM {
		return xerrors.Errorf("envelope: unsupported suite %q", h.Suite)
	}
	if h.Algorithm != mailkey.AlgX25519 || h.Encryption != mailkey.EncAES256GCM {
		return xerrors.Errorf("envelope: unsupported suite %s/%s", h.Algorithm, h.Encryption)
	}
	if h.Domain == "" {
		return xerrors.New("envelope: empty recipient domain")
	}
	if len(h.EphemeralPub) != pubKeyLen {
		return xerrors.Errorf("envelope: ephemeral public key must be %d bytes, got %d", pubKeyLen, len(h.EphemeralPub))
	}
	return nil
}

// AAD is the canonical serialization of the header — the exact bytes bound as
// AEAD associated data. Deterministic, so sender and receiver derive identical
// associated data from the same header without exchanging it.
func (h Header) AAD() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return value.Pack(value.SortedMapOf(map[string]value.Value{
		"v":            value.Long(int64(h.Version)),
		"suite":        value.Utf8(h.Suite),
		"domain":       value.Utf8(h.Domain),
		"kid":          value.Raw(h.Kid[:], true),
		"manifest_id":  value.Raw(h.ManifestID[:], true),
		"alg":          value.Utf8(h.Algorithm),
		"enc":          value.Utf8(h.Encryption),
		"ephemeral_pk": value.Raw(h.EphemeralPub, true),
	}))
}

// deriveAEAD builds the AES-256-GCM cipher from the ECDH secret. Both public
// keys go into the HKDF salt, so a derived key belongs to exactly one
// (ephemeral, recipient) pair.
func deriveAEAD(shared, ephemeralPub, recipientPub []byte) (cipher.AEAD, error) {
	salt := make([]byte, 0, len(ephemeralPub)+len(recipientPub))
	salt = append(salt, ephemeralPub...)
	salt = append(salt, recipientPub...)
	key, err := hkdf.Key(sha256.New, shared, salt, hkdfInfo, aeadKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
