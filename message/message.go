/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package message carries an MKDP1 envelope inside an RFC 5322 message.

The envelope alone is not interoperable: two implementations that agree byte for
byte on the sealed object still cannot exchange mail unless they agree on how it
rides inside a message — which headers survive in the clear, what replaces the
Subject, how the ciphertext is encoded, and how a receiver recognises the message
without trying to decrypt it. That framing is protocol, so it lives here rather
than in any one server.

The shape:

	From, To, Cc, Date, Message-Id, MIME-Version   copied through, so delivery
	                                               and mailbox listing work
	Subject: [Encrypted Message]                   the real one is sealed
	Mail-Key-Encrypted: MKDP1                      what sealed this
	Mail-Key-Suite: <suite>                        which parser opens it
	Content-Type: text/plain; charset=utf-8
	<blank>
	<base64 envelope>

What is NOT in the clear is the point: the real Subject travels inside the sealed
payload, along with every other header. The routing fields are exposed because a
message that cannot be delivered or listed is not mail — that is the honest
boundary of what transport encryption can hide, and it is stated here rather than
left for someone to discover.
*/
package message

import (
	"bytes"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/envelope"
	"golang.org/x/xerrors"
)

// SubjectPlaceholder replaces the real Subject in the outer headers.
const SubjectPlaceholder = "[Encrypted Message]"

// RoutingHeaders are copied to the outer message. Everything else — the real
// Subject included — is sealed.
var RoutingHeaders = []string{"From", "To", "Cc", "Date", "Message-Id", "MIME-Version"}

/*
Seal wraps an entire RFC 5322 message as an MKDP1 message, sealed to a validated
manifest.

Seal ALWAYS seals. It once returned an already-marked message unchanged, as a
convenience against double-sealing — and that convenience was a bypass: the
marks it trusted are two ordinary headers, so anything that could put bytes into
an outbound message (an authenticated submission client, a compromised account,
an internal application) could write them onto plaintext and have the sealing
step hand that plaintext straight back. The sender was then told the message
left protected. Headers are not authentication; only opening an envelope is.
A caller that must not double-seal decides that from state it controls, never
from the message.

Sealing takes a validated mailkey.Result rather than a bare public key on
purpose: the identifiers the envelope authenticates (domain, kid, manifest id)
come from the discovery that authorised the key, so they cannot drift from it.
*/
func Seal(r mailkey.Result, raw []byte) ([]byte, error) {
	env, err := envelope.Seal(r, raw)
	if err != nil {
		return nil, err
	}
	b64, err := env.MarshalBase64()
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	for _, name := range RoutingHeaders {
		if v := HeaderValue(raw, name); v != "" {
			out.WriteString(name + ": " + v + "\r\n")
		}
	}
	out.WriteString("Subject: " + SubjectPlaceholder + "\r\n")
	out.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	out.WriteString(mailkey.HeaderSuite + ": " + env.Header.Suite + "\r\n")
	out.WriteString(mailkey.HeaderEncrypted + ": " + mailkey.Version + "\r\n")
	out.WriteString("\r\n")
	out.WriteString(b64)
	out.WriteString("\r\n")
	return out.Bytes(), nil
}

/*
IsEncrypted reports whether raw is FRAMED as an MKDP1 message: both markers
present, the protocol version and the suite the reader would parse with.

It is a routing hint for a RECEIVER — "try to read this as MKDP1" — and nothing
more. It proves nothing: the markers are unauthenticated headers, so a message
can carry them over any bytes at all. Never use it to conclude that a message
IS protected; that answer only comes from opening the envelope (EnvelopeOf,
Open), which authenticates what it parses.
*/
func IsEncrypted(raw []byte) bool {
	return HeaderValue(raw, mailkey.HeaderEncrypted) == mailkey.Version &&
		HeaderValue(raw, mailkey.HeaderSuite) == envelope.SuiteX25519HKDFSHA256AES256GCM
}

/*
ReservedHeaders are the protocol's own headers. A message SUBMITTED to a server
for sending must never arrive carrying them: Mail-Key-Encrypted and
Mail-Key-Suite describe a sealing that only the sending server can perform, and
Mail-Key advertises the sending domain's manifest, which only that server can
truthfully stamp. A submission that carries any of them is either confused or
forging, and in both cases the server\'s own value is the only correct one.
*/
var ReservedHeaders = []string{mailkey.HeaderEncrypted, mailkey.HeaderSuite, mailkey.HeaderName}

// HasReserved reports whether raw carries any protocol-reserved header — the
// check a submission API makes before accepting a caller-supplied message.
func HasReserved(raw []byte) bool {
	for _, name := range ReservedHeaders {
		if HeaderValue(raw, name) != "" {
			return true
		}
	}
	return false
}

// StripReserved removes every protocol-reserved header from raw. A server
// applies it at the submission boundary so that whatever it later stamps or
// seals is the only such header on the wire.
func StripReserved(raw []byte) []byte {
	for _, name := range ReservedHeaders {
		raw = RemoveHeader(raw, name)
	}
	return raw
}

/*
IsSealed reports whether raw actually CARRIES an MKDP1 envelope — framed as one
AND parsing as one.

This is the proof-shaped question, and the one to ask wherever a claim of
protection is recorded or shown to a person. IsEncrypted only reads two
headers, which anyone can write; passing that test means "try to read this as
MKDP1", never "this was protected". Forging THIS one requires producing a real
envelope, and an envelope that was never sealed to the reader is one they
cannot open — so it can never dress up readable plaintext as protected mail.
*/
func IsSealed(raw []byte) bool {
	_, err := EnvelopeOf(raw)
	return err == nil
}

// EnvelopeOf parses the envelope out of a sealed message WITHOUT decrypting it —
// how a receiver reads the kid to look up a private key before it can open
// anything.
func EnvelopeOf(raw []byte) (*envelope.Envelope, error) {
	if !IsEncrypted(raw) {
		return nil, xerrors.New("not an MKDP1-encrypted message")
	}
	_, body := SplitHeaderBody(raw)
	env, err := envelope.UnmarshalBase64(string(bytes.TrimSpace(body)))
	if err != nil {
		return nil, xerrors.Errorf("decode MKDP1 envelope: %w", err)
	}
	return env, nil
}

// Open opens a sealed message with the private key its kid names, returning the
// original message bytes.
func Open(recipientPriv, raw []byte) ([]byte, error) {
	env, err := EnvelopeOf(raw)
	if err != nil {
		return nil, err
	}
	return envelope.Open(recipientPriv, env)
}

/*
Advertise stamps the Mail-Key header on an outbound message: the id of the
manifest the sending domain publishes.

The header is an advertisement, not a key — a receiver acts on it by fetching the
sender's authority, never by installing what it read. That is why it needs no
trust at all, and why the worst a forged one achieves is a wasted request for the
forger.
*/
func Advertise(raw []byte, domain string, id mailkey.ManifestID) ([]byte, error) {
	// Delegated, never re-implemented: the header grammar is pinned by the
	// published vectors, and a second copy of it here is precisely how two
	// spellings of one advertisement come to exist.
	value, err := discovery.FormatHeader(domain, id)
	if err != nil {
		return nil, err
	}
	return SetHeader(raw, mailkey.HeaderName, value), nil
}

// AdvertisedValue returns the raw Mail-Key header of an inbound message, or ""
// when it carries none. The caller parses it with discovery.ParseHeader, which
// is where the containment rules live.
func AdvertisedValue(raw []byte) string {
	return HeaderValue(raw, mailkey.HeaderName)
}
