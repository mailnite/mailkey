/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package envelope_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/envelope"
	"github.com/mailnite/mailkey/manifest"
)

const testDomain = "example.com"

// receiver mints a key pair and the manifest result a sender would hold after
// discovery — the two halves the protocol has to make agree.
func receiver(t *testing.T, domain string) (*ecdh.PrivateKey, mailkey.Result) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	m, err := manifest.New(domain, now, now.Add(24*time.Hour),
		mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	return priv, mailkey.Result{Manifest: m, ManifestID: manifest.ManifestIDOf(raw), Raw: raw, FetchedAt: now}
}

// TestSealOpen: the happy path, plus the property that makes kid useful — the
// receiver computes the same kid from its own private key that the sender read
// from the manifest, so lookup is a direct index instead of a trial walk.
func TestSealOpen(t *testing.T) {
	priv, res := receiver(t, testDomain)
	plaintext := []byte("Subject: hello\r\n\r\nthe body")

	env, err := envelope.Seal(res, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if env.Header.Kid != res.Manifest.Key.Kid || env.Header.ManifestID != res.ManifestID {
		t.Fatal("the envelope must carry the manifest's identifiers")
	}
	if env.Header.Domain != testDomain || env.Header.Suite != envelope.SuiteX25519HKDFSHA256AES256GCM {
		t.Fatalf("header: %+v", env.Header)
	}
	if bytes.Contains(env.Ciphertext, plaintext) {
		t.Fatal("the plaintext must not appear in the ciphertext")
	}

	got, err := envelope.Open(priv.Bytes(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip changed the plaintext")
	}

	// The receiver indexes its own key by the same kid the sender used.
	kid, err := envelope.KeyIDOfPrivate(testDomain, mailkey.AlgX25519, mailkey.EncAES256GCM, priv)
	if err != nil {
		t.Fatal(err)
	}
	if kid != res.Manifest.Key.Kid {
		t.Fatal("sender and receiver must compute the same kid")
	}

	// Sealing twice gives different bytes (fresh ephemeral key and nonce).
	env2, err := envelope.Seal(res, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(env.Ciphertext, env2.Ciphertext) || bytes.Equal(env.Nonce, env2.Nonce) {
		t.Fatal("each seal must use fresh randomness")
	}
}

// TestMetadataIsAuthenticated is the regression test for SECURITY-REVIEW F-1.
// Every header field is bound as AEAD associated data, so an on-path attacker
// who rewrites ANY of them — to misroute the key lookup, to relabel the
// recipient domain, or to forge the provenance record — turns the message into
// an authentication failure instead of a silently mis-described delivery.
func TestMetadataIsAuthenticated(t *testing.T) {
	priv, res := receiver(t, testDomain)
	plaintext := []byte("bound metadata")

	tamper := map[string]func(*envelope.Envelope){
		"recipient domain": func(e *envelope.Envelope) { e.Header.Domain = "attacker.example" },
		"manifest id":      func(e *envelope.Envelope) { e.Header.ManifestID[0] ^= 0xff },
		"ephemeral key":    func(e *envelope.Envelope) { e.Header.EphemeralPub[0] ^= 0xff },
		"nonce":            func(e *envelope.Envelope) { e.Nonce[0] ^= 0xff },
		"ciphertext":       func(e *envelope.Envelope) { e.Ciphertext[0] ^= 0xff },
	}
	for name, mutate := range tamper {
		env, err := envelope.Seal(res, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		mutate(env)
		if _, err := envelope.Open(priv.Bytes(), env); err == nil {
			t.Errorf("tampered %s: Open must fail", name)
		}
	}

	// kid is bound too, but a rewritten kid is caught even earlier: the
	// receiver's key no longer matches the key the header names.
	env, err := envelope.Seal(res, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	env.Header.Kid[0] ^= 0xff
	if _, err := envelope.Open(priv.Bytes(), env); err == nil {
		t.Error("tampered kid: Open must fail")
	}

	// The AAD itself changes with every bound field — the property the checks
	// above depend on.
	env, _ = envelope.Seal(res, plaintext)
	base, err := env.Header.AAD()
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*envelope.Header){
		"domain":      func(h *envelope.Header) { h.Domain = "other.example" },
		"kid":         func(h *envelope.Header) { h.Kid[5] ^= 1 },
		"manifest id": func(h *envelope.Header) { h.ManifestID[5] ^= 1 },
		"ephemeral":   func(h *envelope.Header) { h.EphemeralPub[5] ^= 1 },
	} {
		h := env.Header
		h.EphemeralPub = append([]byte(nil), env.Header.EphemeralPub...)
		mutate(&h)
		other, err := h.AAD()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(base, other) {
			t.Errorf("AAD must change when %s changes", name)
		}
	}
}

// TestWrongKeyAndCrossDomain: a valid key for the wrong domain must not open an
// envelope, because the domain is inside both the kid preimage and the AAD.
func TestWrongKeyAndCrossDomain(t *testing.T) {
	priv, res := receiver(t, testDomain)
	other, _ := receiver(t, testDomain)
	env, err := envelope.Seal(res, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Open(other.Bytes(), env); err == nil {
		t.Fatal("another key must not open the envelope")
	}
	if _, err := envelope.Open(priv.Bytes()[:31], env); err == nil {
		t.Fatal("a malformed private key must be refused")
	}

	// Same public key, different domain: a different kid, so an envelope sealed
	// for one domain cannot be replayed as the other's.
	sameKeyElsewhere, err := manifest.New("other.example", res.Manifest.IssuedAt, res.Manifest.ExpiresAt,
		mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if sameKeyElsewhere.Key.Kid == res.Manifest.Key.Kid {
		t.Fatal("the same key at another domain must have a different kid")
	}
}

// TestWireRoundTrip: marshalling is canonical and lossless, and a parsed
// envelope still opens.
func TestWireRoundTrip(t *testing.T) {
	priv, res := receiver(t, testDomain)
	plaintext := []byte("wire")
	env, err := envelope.Seal(res, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	again, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("marshalling must be deterministic")
	}
	parsed, err := envelope.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := envelope.Open(priv.Bytes(), parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip through the wire changed the plaintext")
	}

	// base64 carriage in a message body.
	s, err := env.MarshalBase64()
	if err != nil {
		t.Fatal(err)
	}
	fromText, err := envelope.UnmarshalBase64(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Open(priv.Bytes(), fromText); err != nil {
		t.Fatal(err)
	}
}

// TestUnmarshalRejects: hostile framing fails at parse time, before any crypto.
func TestUnmarshalRejects(t *testing.T) {
	_, res := receiver(t, testDomain)
	env, err := envelope.Seal(res, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"empty":     {},
		"garbage":   {0x01, 0x02, 0x03},
		"truncated": good[:len(good)/2],
	} {
		if _, err := envelope.Unmarshal(raw); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	// A foreign suite or version is refused rather than guessed at.
	env.Header.Suite = "some-future-suite"
	if _, err := env.Marshal(); err == nil {
		t.Error("an unknown suite must not marshal")
	}
	env.Header.Suite = envelope.SuiteX25519HKDFSHA256AES256GCM
	env.Header.Version = 99
	if _, err := env.Marshal(); err == nil {
		t.Error("an unknown version must not marshal")
	}
}
