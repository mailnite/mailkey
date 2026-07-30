/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package message_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/message"
)

const testDomain = "example.com"

func receiver(t *testing.T) (*ecdh.PrivateKey, mailkey.Result) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	m, err := manifest.New(testDomain, now, now.Add(24*time.Hour),
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

const original = "From: alice@sender.test\r\n" +
	"To: bob@example.com\r\n" +
	"Date: Mon, 30 Jul 2026 09:00:00 +0000\r\n" +
	"Message-Id: <abc@sender.test>\r\n" +
	"Subject: the quarterly numbers\r\n" +
	"X-Private-Note: internal only\r\n" +
	"\r\n" +
	"the body says something confidential\r\n"

/*
TestSealHidesEverythingButRouting is the framing's actual promise. A sealed
message must expose only what delivery needs, and the Subject is the field people
assume is protected and usually is not — so it is checked by name, along with a
private header and the body.
*/
func TestSealHidesEverythingButRouting(t *testing.T) {
	priv, res := receiver(t)
	sealed, err := message.Seal(res, []byte(original))
	if err != nil {
		t.Fatal(err)
	}
	s := string(sealed)

	for _, secret := range []string{"the quarterly numbers", "internal only", "confidential", "X-Private-Note"} {
		if strings.Contains(s, secret) {
			t.Errorf("%q survives in the clear:\n%s", secret, s)
		}
	}
	// Routing survives, or the message cannot be delivered or listed.
	for _, keep := range []string{"From: alice@sender.test", "To: bob@example.com",
		"Message-Id: <abc@sender.test>", "Date: Mon, 30 Jul 2026"} {
		if !strings.Contains(s, keep) {
			t.Errorf("routing header missing: %q", keep)
		}
	}
	if !strings.Contains(s, "Subject: "+message.SubjectPlaceholder) {
		t.Error("the placeholder Subject is missing")
	}
	// The protocol markers, by their published names.
	if got := message.HeaderValue(sealed, "Mail-Key-Encrypted"); got != "MKDP1" {
		t.Errorf("Mail-Key-Encrypted = %q", got)
	}
	if got := message.HeaderValue(sealed, "Mail-Key-Suite"); got == "" || !strings.HasPrefix(got, "mkdp1-") {
		t.Errorf("Mail-Key-Suite = %q", got)
	}
	// No product name anywhere in the framing, and no deprecated prefix.
	if strings.Contains(s, "Mailnite") || strings.Contains(strings.ToLower(s), "x-mailkey") {
		t.Errorf("framing leaks a product name or an X- prefix:\n%s", s)
	}

	// And it round trips.
	got, err := message.Open(priv.Bytes(), sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("round trip changed the message:\n%q", got)
	}
}

// TestSealIsIdempotent: re-delivery and per-recipient fan-out must never
// double-seal, so the caller does not have to remember at every call site.
func TestSealIsIdempotent(t *testing.T) {
	priv, res := receiver(t)
	once, err := message.Seal(res, []byte(original))
	if err != nil {
		t.Fatal(err)
	}
	twice, err := message.Seal(res, once)
	if err != nil {
		t.Fatal(err)
	}
	if string(twice) != string(once) {
		t.Fatal("sealing an already-sealed message must return it unchanged")
	}
	if got, err := message.Open(priv.Bytes(), twice); err != nil || string(got) != original {
		t.Fatalf("a once-sealed message must open in one step: %v", err)
	}
}

// TestRecognitionRequiresBothMarkers: the reader chooses its parser from what the
// message declares. A marker without a suite, or a suite it does not implement,
// is not something to guess at.
func TestRecognitionRequiresBothMarkers(t *testing.T) {
	_, res := receiver(t)
	sealed, err := message.Seal(res, []byte(original))
	if err != nil {
		t.Fatal(err)
	}
	if !message.IsEncrypted(sealed) {
		t.Fatal("a sealed message must be recognised")
	}
	for name, mutated := range map[string][]byte{
		"no protocol marker": message.RemoveHeader(sealed, "Mail-Key-Encrypted"),
		"no suite":           message.RemoveHeader(sealed, "Mail-Key-Suite"),
		"unknown suite":      message.SetHeader(sealed, "Mail-Key-Suite", "mkdp1-something-else"),
		"wrong protocol":     message.SetHeader(sealed, "Mail-Key-Encrypted", "MKDP2"),
		"plain message":      []byte(original),
	} {
		if message.IsEncrypted(mutated) {
			t.Errorf("%s: must not be recognised as sealed", name)
		}
		if _, err := message.EnvelopeOf(mutated); err == nil {
			t.Errorf("%s: must not yield an envelope", name)
		}
	}
}

/*
TestAdvertiseIsOneFieldAndMatchesDiscovery pins two things at once: the header
this package writes is exactly the one the protocol's own formatter produces, and
exactly one of it survives — the DKIM rule, since duplicate field names are
resolved bottom-up and a message that arrived with its own Mail-Key would
otherwise get one instance signed while a receiver read another.
*/
func TestAdvertiseIsOneFieldAndMatchesDiscovery(t *testing.T) {
	_, res := receiver(t)
	hostile := "From: alice@sender.test\r\n" +
		"Mail-Key: v=MKDP1; d=evil.test; id=AAAA; mode=https\r\n" +
		"Subject: hi\r\n\r\nbody\r\n"

	out, err := message.Advertise([]byte(hostile), testDomain, res.ManifestID)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := message.SplitHeaderBody(out)
	if n := strings.Count(strings.ToLower(string(head)), "mail-key:"); n != 1 {
		t.Fatalf("header block has %d Mail-Key fields, want exactly 1:\n%s", n, head)
	}
	want, err := discovery.FormatHeader(testDomain, res.ManifestID)
	if err != nil {
		t.Fatal(err)
	}
	if got := message.AdvertisedValue(out); got != want {
		t.Fatalf("advertised %q, discovery formats %q", got, want)
	}
	// And the protocol's parser reads back what we wrote.
	ad, err := discovery.ParseHeader(message.AdvertisedValue(out))
	if err != nil {
		t.Fatalf("our own advertisement must parse: %v", err)
	}
	if ad.Domain != testDomain || !ad.HasID || ad.ManifestID != res.ManifestID {
		t.Fatalf("parsed back as %+v", ad)
	}
}

// TestHeaderHelpers covers the shapes real mail arrives in — folded values, mixed
// case, and body text that looks like a header.
func TestHeaderHelpers(t *testing.T) {
	raw := []byte("From: a@b.test\r\nMAIL-KEY: v=MKDP1; d=example.com;\r\n id=XYZ;\r\n\tmode=https\r\n" +
		"\r\nMail-Key: this line is body text\r\n")
	if got := message.HeaderValue(raw, "Mail-Key"); got != "v=MKDP1; d=example.com; id=XYZ; mode=https" {
		t.Fatalf("folded/mixed-case read: %q", got)
	}
	head, body := message.SplitHeaderBody(raw)
	if !strings.Contains(string(body), "body text") || strings.Contains(string(head), "body text") {
		t.Fatal("the header/body split is wrong")
	}
	// Removing a field takes its folded continuations with it and leaves the body.
	out := message.RemoveHeader(raw, "Mail-Key")
	if strings.Contains(string(out), "id=XYZ") || strings.Contains(string(out), "mode=https") {
		t.Fatalf("a folded continuation was left behind:\n%q", out)
	}
	if !strings.Contains(string(out), "body text") || !strings.Contains(string(out), "From: a@b.test") {
		t.Fatalf("removal disturbed the rest:\n%q", out)
	}
	// Absent field, and a header-only message.
	if got := message.HeaderValue([]byte("From: a@b.test\r\n\r\nbody\r\n"), "Mail-Key"); got != "" {
		t.Fatalf("absent field returned %q", got)
	}
	if got := message.HeaderValue([]byte("Mail-Key: v=MKDP1\r\n"), "Mail-Key"); got != "v=MKDP1" {
		t.Fatalf("header-only message: %q", got)
	}
}
