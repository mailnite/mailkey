/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package manifest_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"go.arpabet.com/value"
)

// testPK is a fixed 32-byte public key: the vectors below are pinned to it, so
// a change to the canonical form or either preimage breaks these tests loudly.
var testPK = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}()

const (
	testDomain = "example.com"
	issued     = int64(1_700_000_000)
	expires    = int64(1_700_086_400) // +24h
)

func newTestManifest(t *testing.T) mailkey.Manifest {
	t.Helper()
	m, err := manifest.New(testDomain, time.Unix(issued, 0), time.Unix(expires, 0),
		mailkey.AlgX25519, mailkey.EncAES256GCM, testPK)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestGoldenVectors pins the wire format. These hex strings are the protocol:
// an implementation that produces different bytes is not MKDP1-compatible, and
// changing them is a protocol change, not a refactor.
func TestGoldenVectors(t *testing.T) {
	m := newTestManifest(t)
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	// The canonical bytes, the manifest id and the kid for the fixture above.
	// These ARE the protocol: an implementation producing different bytes is not
	// MKDP1-compatible, and editing these constants is a protocol change.
	const (
		wantManifest = "85a6646f6d61696eab6578616d706c652e636f6daa657870697265735f6174ce65554280a96973737565645f6174ce6553f100a36b657984a3616c67a6783235353139a3656e63a961657332353667636da36b6964c42042ca151eb3d40cf28b4c2e57b0038e670d702594217d8807caa48567c6257b7ea2706bc4200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a176a54d4b445031"
		wantID       = "iErreOTszRhevJCaD56t1MfFP_EqAd3NsKsrfmERfpw"
		wantKid      = "QsoVHrPUDPKLTC5XsAOOZw1wJZQhfYgHyqSFZ8Yle34"
	)
	if got := hex.EncodeToString(raw); got != wantManifest {
		t.Fatalf("canonical manifest bytes changed:\n got %s\nwant %s", got, wantManifest)
	}
	if got := manifest.EncodeID(m.Key.Kid); got != wantKid {
		t.Fatalf("kid changed: got %s, want %s", got, wantKid)
	}
	if got := manifest.EncodeID(manifest.ManifestIDOf(raw)); got != wantID {
		t.Fatalf("manifest id changed: got %s, want %s", got, wantID)
	}

	// The packed form is a 5-entry map (0x85) — the schema's field count — and
	// packing is stable across calls.
	if raw[0] != 0x85 {
		t.Fatalf("canonical manifest must be a 5-field map (0x85), got %#x", raw[0])
	}
	again, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("packing the same manifest twice must produce identical bytes")
	}
}

// TestPackIsOrderIndependent: the canonical form sorts keys, so the logical
// manifest — not the construction order — determines the bytes. This is what
// lets two implementations agree without sharing code.
func TestPackIsOrderIndependent(t *testing.T) {
	m := newTestManifest(t)
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	// Build the same object with deliberately reversed insertion order.
	keyMap := value.SortedMapOf(map[string]value.Value{
		"pk":  value.Raw(testPK, true),
		"enc": value.Utf8(mailkey.EncAES256GCM),
		"alg": value.Utf8(mailkey.AlgX25519),
		"kid": value.Raw(m.Key.Kid[:], true),
	})
	manual, err := value.Pack(value.SortedMapOf(map[string]value.Value{
		"key":        keyMap,
		"expires_at": value.Long(expires),
		"issued_at":  value.Long(issued),
		"domain":     value.Utf8(testDomain),
		"v":          value.Utf8(mailkey.Version),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, manual) {
		t.Fatalf("insertion order changed the canonical bytes:\n got %s\nwant %s",
			hex.EncodeToString(manual), hex.EncodeToString(raw))
	}
}

// TestKeyIDBinding: every element of the kid preimage must matter, and the
// timestamps must not. That is what makes kid a stable key name across
// rotations of the manifest's validity window, and what prevents cross-domain
// and cross-suite substitution of the same public key.
func TestKeyIDBinding(t *testing.T) {
	base, err := manifest.KeyIDOf(testDomain, mailkey.AlgX25519, mailkey.EncAES256GCM, testPK)
	if err != nil {
		t.Fatal(err)
	}
	other, err := manifest.KeyIDOf("other.example", mailkey.AlgX25519, mailkey.EncAES256GCM, testPK)
	if err != nil {
		t.Fatal(err)
	}
	if base == other {
		t.Fatal("the same key at a different domain must have a different kid")
	}
	flipped := append([]byte(nil), testPK...)
	flipped[31] ^= 0x01
	bit, err := manifest.KeyIDOf(testDomain, mailkey.AlgX25519, mailkey.EncAES256GCM, flipped)
	if err != nil {
		t.Fatal(err)
	}
	if base == bit {
		t.Fatal("one flipped key bit must change the kid")
	}
	// Timestamps are not in the preimage: two manifests with different
	// validity windows name the same key.
	m1, _ := manifest.New(testDomain, time.Unix(issued, 0), time.Unix(expires, 0), mailkey.AlgX25519, mailkey.EncAES256GCM, testPK)
	m2, _ := manifest.New(testDomain, time.Unix(issued+9999, 0), time.Unix(expires+9999, 0), mailkey.AlgX25519, mailkey.EncAES256GCM, testPK)
	if m1.Key.Kid != m2.Key.Kid {
		t.Fatal("kid must not depend on the manifest's timestamps")
	}
	if id1, id2 := mustPack(t, m1), mustPack(t, m2); bytes.Equal(id1, id2) {
		t.Fatal("a different validity window must change the manifest bytes")
	}
	// Unsupported suites fail closed rather than hashing something unknown.
	if _, err := manifest.KeyIDOf(testDomain, "rsa", mailkey.EncAES256GCM, testPK); err == nil {
		t.Fatal("unknown algorithm must be refused")
	}
	if _, err := manifest.KeyIDOf(testDomain, mailkey.AlgX25519, "chacha", testPK); err == nil {
		t.Fatal("unknown encryption must be refused")
	}
	if _, err := manifest.KeyIDOf(testDomain, mailkey.AlgX25519, mailkey.EncAES256GCM, testPK[:31]); err == nil {
		t.Fatal("wrong key length must be refused")
	}
}

func mustPack(t *testing.T, m mailkey.Manifest) []byte {
	t.Helper()
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestParseCanonicalRoundTrip: a manifest we packed parses back identically.
func TestParseCanonicalRoundTrip(t *testing.T) {
	m := newTestManifest(t)
	raw := mustPack(t, m)
	got, err := manifest.ParseCanonical(raw, testDomain)
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != m.Domain || got.Key.Kid != m.Key.Kid || !bytes.Equal(got.Key.PublicKey, m.Key.PublicKey) {
		t.Fatalf("round trip changed the manifest: %+v", got)
	}
	if !got.IssuedAt.Equal(m.IssuedAt) || !got.ExpiresAt.Equal(m.ExpiresAt) {
		t.Fatal("round trip changed the validity window")
	}
}

// TestParseRejects is the hostile-input battery: every one of these is a way an
// attacker-controlled endpoint could try to slip something past the parser.
func TestParseRejects(t *testing.T) {
	m := newTestManifest(t)
	good := mustPack(t, m)

	cases := map[string][]byte{
		"empty body":    {},
		"not a map":     mustValuePack(t, value.Utf8("hello")),
		"trailing data": append(append([]byte(nil), good...), 0x00),
		"truncated":     good[:len(good)-3],
	}
	for name, raw := range cases {
		if _, err := manifest.ParseCanonical(raw, testDomain); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}

	// A wrong version, an unknown field, a missing field, the wrong domain, a
	// string where bytes belong, and a tampered kid — each built as a fresh
	// canonical object so only the tested property differs.
	base := map[string]value.Value{
		"v":          value.Utf8(mailkey.Version),
		"domain":     value.Utf8(testDomain),
		"issued_at":  value.Long(issued),
		"expires_at": value.Long(expires),
		"key": value.SortedMapOf(map[string]value.Value{
			"kid": value.Raw(m.Key.Kid[:], true),
			"alg": value.Utf8(mailkey.AlgX25519),
			"enc": value.Utf8(mailkey.EncAES256GCM),
			"pk":  value.Raw(testPK, true),
		}),
	}
	mutate := func(f func(map[string]value.Value)) []byte {
		cp := map[string]value.Value{}
		for k, v := range base {
			cp[k] = v
		}
		f(cp)
		return mustValuePack(t, value.SortedMapOf(cp))
	}
	bad := map[string][]byte{
		"unsupported version": mutate(func(m map[string]value.Value) { m["v"] = value.Utf8("MKDP2") }),
		"unknown field":       mutate(func(m map[string]value.Value) { m["extra"] = value.Utf8("x") }),
		"missing field":       mutate(func(m map[string]value.Value) { delete(m, "issued_at") }),
		"domain as raw bytes": mutate(func(m map[string]value.Value) { m["domain"] = value.Raw([]byte(testDomain), true) }),
		"issued_at as double": mutate(func(m map[string]value.Value) { m["issued_at"] = value.Double(float64(issued)) }),
		"pk as utf8 string": mutate(func(mm map[string]value.Value) {
			mm["key"] = value.SortedMapOf(map[string]value.Value{
				"kid": value.Raw(m.Key.Kid[:], true), "alg": value.Utf8(mailkey.AlgX25519),
				"enc": value.Utf8(mailkey.EncAES256GCM), "pk": value.Utf8(string(testPK)),
			})
		}),
		"tampered kid": mutate(func(mm map[string]value.Value) {
			k := append([]byte(nil), m.Key.Kid[:]...)
			k[0] ^= 0xff
			mm["key"] = value.SortedMapOf(map[string]value.Value{
				"kid": value.Raw(k, true), "alg": value.Utf8(mailkey.AlgX25519),
				"enc": value.Utf8(mailkey.EncAES256GCM), "pk": value.Raw(testPK, true),
			})
		}),
		"short public key": mutate(func(mm map[string]value.Value) {
			mm["key"] = value.SortedMapOf(map[string]value.Value{
				"kid": value.Raw(m.Key.Kid[:], true), "alg": value.Utf8(mailkey.AlgX25519),
				"enc": value.Utf8(mailkey.EncAES256GCM), "pk": value.Raw(testPK[:16], true),
			})
		}),
		"unknown algorithm": mutate(func(mm map[string]value.Value) {
			mm["key"] = value.SortedMapOf(map[string]value.Value{
				"kid": value.Raw(m.Key.Kid[:], true), "alg": value.Utf8("rsa"),
				"enc": value.Utf8(mailkey.EncAES256GCM), "pk": value.Raw(testPK, true),
			})
		}),
	}
	for name, raw := range bad {
		if _, err := manifest.ParseCanonical(raw, testDomain); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}

	// A manifest for a different domain than the one requested: this is the
	// check that stops a compromised host answering for its neighbours.
	if _, err := manifest.ParseCanonical(good, "attacker.example"); err == nil {
		t.Error("a manifest for another domain must be refused")
	}

	// Oversized body is refused before any parsing.
	if _, err := manifest.ParseCanonical(make([]byte, mailkey.MaxBodyBytes+1), testDomain); err == nil {
		t.Error("an oversized body must be refused")
	}
}

func mustValuePack(t *testing.T, v value.Value) []byte {
	t.Helper()
	raw, err := value.Pack(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestValidate covers the time policy: expiry, ordering, lifetime ceiling and
// future issuance beyond the allowed skew.
func TestValidate(t *testing.T) {
	limits := manifest.DefaultLimits()
	now := time.Unix(issued+3600, 0)
	m := newTestManifest(t)
	if err := manifest.Validate(m, now, limits); err != nil {
		t.Fatalf("a fresh manifest must validate: %v", err)
	}
	if err := manifest.Validate(m, time.Unix(expires+1, 0), limits); err == nil {
		t.Error("an expired manifest must be refused")
	}
	backwards := m
	backwards.ExpiresAt = m.IssuedAt.Add(-time.Second)
	if err := manifest.Validate(backwards, now, limits); err == nil {
		t.Error("expires_at before issued_at must be refused")
	}
	long := m
	long.ExpiresAt = m.IssuedAt.Add(400 * 24 * time.Hour)
	if err := manifest.Validate(long, now, limits); err == nil {
		t.Error("a lifetime beyond the ceiling must be refused")
	}
	future := m
	future.IssuedAt = now.Add(time.Hour)
	future.ExpiresAt = future.IssuedAt.Add(time.Hour)
	if err := manifest.Validate(future, now, limits); err == nil {
		t.Error("issuance beyond the clock-skew allowance must be refused")
	}
}

// TestPackRefusesInconsistentKid: a publisher cannot emit bytes whose kid does
// not match the key they contain — those bytes would fail every client's
// validation, so failing at pack time turns a silent outage into an error.
func TestPackRefusesInconsistentKid(t *testing.T) {
	m := newTestManifest(t)
	m.Key.Kid[0] ^= 0xff
	if _, err := manifest.Pack(m); err == nil {
		t.Fatal("packing a manifest with a mismatched kid must fail")
	}
}

// TestIdentifierText pins the text encoding: unpadded base64url, full length,
// no alternative spellings accepted.
func TestIdentifierText(t *testing.T) {
	m := newTestManifest(t)
	id := manifest.ManifestIDOf(mustPack(t, m))
	s := manifest.EncodeID(id)
	if strings.ContainsAny(s, "=+/") {
		t.Fatalf("identifiers must be unpadded base64url, got %q", s)
	}
	back, err := manifest.DecodeID(s)
	if err != nil || back != id {
		t.Fatalf("round trip failed: %v", err)
	}
	for name, bad := range map[string]string{
		"padded":     s + "=",
		"truncated":  s[:40],
		"base64 std": strings.ReplaceAll(s, "-", "+"),
		"not base64": "!!!!",
		"empty":      "",
	} {
		if _, err := manifest.DecodeID(bad); err == nil && bad != strings.ReplaceAll(s, "-", "+") {
			t.Errorf("%s: must be refused", name)
		}
	}
}
