/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package mailkey_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/envelope"
	"github.com/mailnite/mailkey/identity"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/message"
)

/*
testdata/vectors.json is the PUBLISHED interoperability artifact — the file a
third-party implementation is checked against, and the reason MKDP1 can have more
than one implementation at all (test plan §10).

This test exists to keep the file honest. Published vectors that drift from the
code are worse than no vectors: an implementer would chase a difference that is
not in the protocol. So every value in the file is recomputed here from the
inputs the file itself states, and a mismatch fails — whichever side moved.

Editing these values is a PROTOCOL CHANGE, not a test fix.
*/

type vectorFile struct {
	Protocol string `json:"protocol"`
	Manifest struct {
		Input struct {
			Domain       string `json:"domain"`
			IssuedAt     int64  `json:"issued_at"`
			ExpiresAt    int64  `json:"expires_at"`
			Alg          string `json:"alg"`
			Enc          string `json:"enc"`
			PublicKeyHex string `json:"public_key_hex"`
		} `json:"input"`
		CanonicalBytesHex string `json:"canonical_bytes_hex"`
		CanonicalBytesLen int    `json:"canonical_bytes_len"`
		ManifestID        string `json:"manifest_id"`
		Kid               string `json:"kid"`
		DNSOwnerName      string `json:"dns_owner_name"`
		DNSTxtValue       string `json:"dns_txt_value"`
		MailKeyHeader     string `json:"mail_key_header"`
		DiscoveryURL      string `json:"discovery_url"`
		MediaType         string `json:"media_type"`
		WellKnownPath     string `json:"well_known_path"`
	} `json:"manifest"`
	Message struct {
		HeaderEncrypted     string   `json:"header_encrypted"`
		HeaderSuite         string   `json:"header_suite"`
		HeaderAdvertisement string   `json:"header_advertisement"`
		EncryptedValue      string   `json:"encrypted_value"`
		SubjectPlaceholder  string   `json:"subject_placeholder"`
		RoutingHeaders      []string `json:"routing_headers"`
		Inner               string   `json:"inner"`
		SealedBase64        string   `json:"sealed_base64"`
	} `json:"message"`
	Envelope struct {
		Suite               string `json:"suite"`
		RecipientPrivateHex string `json:"recipient_private_hex"`
		RecipientPublicHex  string `json:"recipient_public_hex"`
		ManifestBytesHex    string `json:"manifest_bytes_hex"`
		ManifestID          string `json:"manifest_id"`
		Kid                 string `json:"kid"`
		WireBase64          string `json:"wire_base64"`
		Plaintext           string `json:"plaintext"`
	} `json:"envelope"`
	Identity struct {
		Alg                 string `json:"alg"`
		Domain              string `json:"domain"`
		SeedHex             string `json:"seed_hex"`
		PublicKeyHex        string `json:"public_key_hex"`
		Fingerprint         string `json:"fingerprint"`
		FingerprintType     string `json:"fingerprint_type"`
		ManifestContext     string `json:"manifest_context"`
		ManifestBytesHex    string `json:"manifest_bytes_hex"`
		SignatureBase64     string `json:"signature_base64"`
		HeaderIdentity      string `json:"header_identity"`
		HeaderSigner        string `json:"header_signer"`
		HeaderSignature     string `json:"header_signature"`
		HeaderIdentityName  string `json:"header_identity_name"`
		HeaderSignerName    string `json:"header_signer_name"`
		HeaderSignatureName string `json:"header_signature_name"`
	} `json:"identity"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("the published vectors must exist: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("published vectors must be valid JSON: %v", err)
	}
	return v
}

// TestPublishedManifestVectors recomputes every published manifest identifier
// from the published inputs.
func TestPublishedManifestVectors(t *testing.T) {
	v := loadVectors(t)
	if v.Protocol != mailkey.Version {
		t.Fatalf("vectors are for %q, this is %q", v.Protocol, mailkey.Version)
	}
	in := v.Manifest.Input
	pk, err := hex.DecodeString(in.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.New(in.Domain, time.Unix(in.IssuedAt, 0), time.Unix(in.ExpiresAt, 0), in.Alg, in.Enc, pk)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(raw); got != v.Manifest.CanonicalBytesHex {
		t.Fatalf("canonical bytes differ from the published vector:\n got %s\nwant %s", got, v.Manifest.CanonicalBytesHex)
	}
	if len(raw) != v.Manifest.CanonicalBytesLen {
		t.Fatalf("canonical length = %d, published %d", len(raw), v.Manifest.CanonicalBytesLen)
	}
	if got := manifest.EncodeID(manifest.ManifestIDOf(raw)); got != v.Manifest.ManifestID {
		t.Fatalf("manifest_id = %s, published %s", got, v.Manifest.ManifestID)
	}
	if got := manifest.EncodeID(m.Key.Kid); got != v.Manifest.Kid {
		t.Fatalf("kid = %s, published %s", got, v.Manifest.Kid)
	}

	// The derived names and the two advertisement forms are part of the vector:
	// an implementation that agrees on the bytes but advertises them differently
	// is still not interoperable.
	name, err := discovery.DNSName(in.Domain)
	if err != nil || name != v.Manifest.DNSOwnerName {
		t.Fatalf("dns owner name = %q (%v), published %q", name, err, v.Manifest.DNSOwnerName)
	}
	if got := discovery.FormatDNS(mailkey.Fingerprint{}, false, manifest.ManifestIDOf(raw)); got != v.Manifest.DNSTxtValue {
		t.Fatalf("dns txt = %q, published %q", got, v.Manifest.DNSTxtValue)
	}
	hdr, err := discovery.FormatHeader(in.Domain, manifest.ManifestIDOf(raw))
	if err != nil || hdr != v.Manifest.MailKeyHeader {
		t.Fatalf("header = %q (%v), published %q", hdr, err, v.Manifest.MailKeyHeader)
	}
	u, err := discovery.DiscoveryURL(in.Domain)
	if err != nil || u.String() != v.Manifest.DiscoveryURL {
		t.Fatalf("discovery url = %v (%v), published %q", u, err, v.Manifest.DiscoveryURL)
	}
	// The transport constants are part of the published contract too: an
	// implementation that agrees on every byte but serves them at another path,
	// or labels them a type a peer refuses, still does not interoperate.
	if mailkey.MediaType != v.Manifest.MediaType {
		t.Fatalf("media type = %q, published %q", mailkey.MediaType, v.Manifest.MediaType)
	}
	if mailkey.WellKnownPath != v.Manifest.WellKnownPath {
		t.Fatalf("well-known path = %q, published %q", mailkey.WellKnownPath, v.Manifest.WellKnownPath)
	}

	// And the published bytes parse back as canonical for the published domain —
	// the check a receiving implementation performs.
	back, err := manifest.ParseCanonical(raw, in.Domain)
	if err != nil {
		t.Fatalf("published bytes must validate as canonical: %v", err)
	}
	if back.Key.Kid != m.Key.Kid {
		t.Fatal("parsing the published bytes must recover the published kid")
	}

	// Timestamps are outside the kid preimage, so a manifest reissued with new
	// validity names the SAME key. An implementation that folded timestamps into
	// the kid would rotate the identifier on every republication.
	later, err := manifest.New(in.Domain, time.Unix(in.IssuedAt+86400, 0), time.Unix(in.ExpiresAt+86400, 0), in.Alg, in.Enc, pk)
	if err != nil {
		t.Fatal(err)
	}
	if later.Key.Kid != m.Key.Kid {
		t.Fatal("the kid must not depend on the manifest's timestamps")
	}
	if lraw, err := manifest.Pack(later); err != nil || manifest.ManifestIDOf(lraw) == manifest.ManifestIDOf(raw) {
		t.Fatal("the manifest_id must change when any field changes")
	}
}

/*
TestPublishedEnvelopeVector opens the published envelope with the published
private key.

It is a DECRYPT vector rather than an encrypt vector, and that is forced by the
construction: every envelope carries a fresh ephemeral key and nonce, so no
implementation can reproduce another's bytes. What CAN be shared is the ability
to open them, which is the property that actually matters for interoperability —
and it transitively verifies the whole suite, since the header fields are
authenticated as associated data and a wrong understanding of any of them makes
the tag fail.
*/
func TestPublishedEnvelopeVector(t *testing.T) {
	v := loadVectors(t)
	if v.Envelope.Suite != envelope.SuiteX25519HKDFSHA256AES256GCM {
		t.Fatalf("vector suite %q, this implementation %q", v.Envelope.Suite, envelope.SuiteX25519HKDFSHA256AES256GCM)
	}
	priv, err := hex.DecodeString(v.Envelope.RecipientPrivateHex)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := base64.StdEncoding.DecodeString(v.Envelope.WireBase64)
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Unmarshal(wire)
	if err != nil {
		t.Fatalf("the published envelope must parse: %v", err)
	}
	// The envelope names its key and its fetch, and both are published.
	if got := manifest.EncodeID(env.Header.Kid); got != v.Envelope.Kid {
		t.Fatalf("envelope kid = %s, published %s", got, v.Envelope.Kid)
	}
	if got := manifest.EncodeID(env.Header.ManifestID); got != v.Envelope.ManifestID {
		t.Fatalf("envelope manifest_id = %s, published %s", got, v.Envelope.ManifestID)
	}
	got, err := envelope.Open(priv, env)
	if err != nil {
		t.Fatalf("the published envelope must open with the published key: %v", err)
	}
	if string(got) != v.Envelope.Plaintext {
		t.Fatalf("plaintext differs:\n got %q\nwant %q", got, v.Envelope.Plaintext)
	}

	// The published kid really names the published key pair — the receiver's key
	// generation and a sender's calculation must agree (test plan §10).
	pub, err := hex.DecodeString(v.Envelope.RecipientPublicHex)
	if err != nil {
		t.Fatal(err)
	}
	mraw, err := hex.DecodeString(v.Envelope.ManifestBytesHex)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.ParseCanonical(mraw, "example.com")
	if err != nil {
		t.Fatalf("the published envelope's manifest must validate: %v", err)
	}
	kid, err := manifest.KeyIDOf(m.Domain, m.Key.Algorithm, m.Key.Encryption, pub)
	if err != nil {
		t.Fatal(err)
	}
	if kid != env.Header.Kid {
		t.Fatal("the sender's computed kid must equal the one the envelope names")
	}

	// Tampering with any authenticated field fails, and the vector proves it on
	// PUBLISHED bytes rather than freshly generated ones.
	for name, mutate := range map[string]func(*envelope.Envelope){
		"domain":      func(e *envelope.Envelope) { e.Header.Domain = "attacker.test" },
		"kid":         func(e *envelope.Envelope) { e.Header.Kid[0] ^= 1 },
		"manifest id": func(e *envelope.Envelope) { e.Header.ManifestID[0] ^= 1 },
		"suite":       func(e *envelope.Envelope) { e.Header.Suite = "other-suite" },
		"ciphertext":  func(e *envelope.Envelope) { e.Ciphertext[0] ^= 1 },
	} {
		bad, err := envelope.Unmarshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		mutate(bad)
		if _, err := envelope.Open(priv, bad); err == nil {
			t.Errorf("tampering with the %s must fail authentication", name)
		}
	}
}

/*
TestPublishedMessageVector pins the mail FRAMING, which is protocol for the same
reason the envelope is: two implementations that agree byte for byte on the
sealed object still cannot exchange mail unless they agree on how it rides inside
a message.

The header names are checked against the constants, so renaming one without
republishing the vectors fails here — and the secrecy assertion is the one that
matters, because a framing that leaks the Subject would pass every round-trip
test while failing its only real promise.
*/
func TestPublishedMessageVector(t *testing.T) {
	v := loadVectors(t)
	if mailkey.HeaderEncrypted != v.Message.HeaderEncrypted ||
		mailkey.HeaderSuite != v.Message.HeaderSuite ||
		mailkey.HeaderName != v.Message.HeaderAdvertisement {
		t.Fatalf("header names differ from the published vector: %q/%q/%q vs %q/%q/%q",
			mailkey.HeaderEncrypted, mailkey.HeaderSuite, mailkey.HeaderName,
			v.Message.HeaderEncrypted, v.Message.HeaderSuite, v.Message.HeaderAdvertisement)
	}
	// No deprecated prefix and no product name — the reason these were renamed.
	for _, h := range []string{mailkey.HeaderName, mailkey.HeaderEncrypted, mailkey.HeaderSuite} {
		if strings.HasPrefix(strings.ToLower(h), "x-") {
			t.Errorf("%q carries an X- prefix; RFC 6648 deprecated that convention", h)
		}
		if strings.Contains(strings.ToLower(h), "mailnite") {
			t.Errorf("%q names the product rather than the protocol", h)
		}
	}
	if message.SubjectPlaceholder != v.Message.SubjectPlaceholder {
		t.Fatalf("subject placeholder = %q, published %q", message.SubjectPlaceholder, v.Message.SubjectPlaceholder)
	}
	if strings.Join(message.RoutingHeaders, ",") != strings.Join(v.Message.RoutingHeaders, ",") {
		t.Fatalf("routing headers = %v, published %v", message.RoutingHeaders, v.Message.RoutingHeaders)
	}

	sealed, err := base64.StdEncoding.DecodeString(v.Message.SealedBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !message.IsEncrypted(sealed) {
		t.Fatal("the published sealed message must be recognised as MKDP1")
	}
	// What must NOT be in the clear.
	if strings.Contains(string(sealed), "the real subject is sealed") ||
		strings.Contains(string(sealed), "the body") {
		t.Fatal("the published framing leaks the Subject or the body")
	}
	priv, err := hex.DecodeString(v.Envelope.RecipientPrivateHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := message.Open(priv, sealed)
	if err != nil {
		t.Fatalf("the published sealed message must open with the published key: %v", err)
	}
	if string(got) != v.Message.Inner {
		t.Fatalf("opened message differs from the published inner message:\n%q", got)
	}
}

/*
TestPublishedIdentityVector recomputes every identity value in the vectors file.

The point of a vector file is that a second implementation can check itself
against it. That only holds if the file cannot drift from the code — a stale
vector is worse than no vector, because it certifies agreement that no longer
exists. So nothing here is read and trusted: the fingerprint, the signature and
all three response fields are DERIVED from the published seed and manifest bytes
and compared.
*/
func TestPublishedIdentityVector(t *testing.T) {
	v := loadVectors(t)
	in := v.Identity

	seed := mustHex(t, in.SeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pk := priv.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(pk); got != in.PublicKeyHex {
		t.Fatalf("public key = %s, vector says %s", got, in.PublicKeyHex)
	}

	fp, err := identity.FingerprintOf(in.Domain, pk)
	if err != nil {
		t.Fatal(err)
	}
	if got := manifest.EncodeID(fp); got != in.Fingerprint {
		t.Fatalf("fingerprint = %s, vector says %s", got, in.Fingerprint)
	}
	if in.FingerprintType != identity.FingerprintType || in.Alg != identity.Alg {
		t.Fatalf("vector names type/alg %q/%q, code says %q/%q",
			in.FingerprintType, in.Alg, identity.FingerprintType, identity.Alg)
	}
	if in.ManifestContext != identity.ManifestContext {
		t.Fatalf("vector context %q, code says %q", in.ManifestContext, identity.ManifestContext)
	}

	// The signature is over the SAME manifest bytes the manifest vector pins, so
	// the two blocks cannot describe different objects.
	raw := mustHex(t, in.ManifestBytesHex)
	if got := hex.EncodeToString(raw); got != v.Manifest.CanonicalBytesHex {
		t.Fatal("the identity vector signs different bytes than the manifest vector publishes")
	}
	sig := mustB64(t, in.SignatureBase64)
	if err := identity.VerifyManifest(pk, in.Domain, raw, sig); err != nil {
		t.Fatalf("the published signature does not verify: %v", err)
	}
	// Ed25519 is deterministic, so the signature is reproducible byte for byte —
	// which is what lets another implementation check its own signing, not just
	// its verification.
	again, err := identity.SignManifest(priv, in.Domain, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, sig) {
		t.Fatal("re-signing produced different bytes — the vector is not reproducible")
	}

	// The response fields, exactly as an implementation must emit and parse them.
	if in.HeaderIdentityName != mailkey.HeaderIdentity ||
		in.HeaderSignerName != mailkey.HeaderSigner ||
		in.HeaderSignatureName != mailkey.HeaderSignature {
		t.Fatal("the vector names different response fields than the code")
	}
	h := http.Header{}
	identity.WriteProof(h, &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig})
	for name, want := range map[string]string{
		mailkey.HeaderIdentity:  in.HeaderIdentity,
		mailkey.HeaderSigner:    in.HeaderSigner,
		mailkey.HeaderSignature: in.HeaderSignature,
	} {
		if got := h.Get(name); got != want {
			t.Fatalf("%s = %q, vector says %q", name, got, want)
		}
	}
	proof, found, err := identity.ReadProof(h)
	if err != nil || !found {
		t.Fatalf("the vector's own fields must parse: found=%v err=%v", found, err)
	}
	if err := identity.Check(proof, in.Domain, raw); err != nil {
		t.Fatalf("the vector's proof must check out: %v", err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return b
}
