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

// sealedFixture builds one real envelope's wire bytes, as a fuzz seed.
func sealedFixture() ([]byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().Truncate(time.Second)
	m, err := manifest.New("example.com", now, now.Add(24*time.Hour),
		mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		return nil, err
	}
	env, err := envelope.Seal(mailkey.Result{Manifest: m, ManifestID: manifest.ManifestIDOf(raw), Raw: raw}, []byte("seed body"))
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

/*
FuzzUnmarshal fuzzes the envelope metadata parser — the parser that runs on
attacker-supplied bytes for every encrypted message that arrives.

Two properties, and the second is the one worth fuzzing for:

  - no panic and no unbounded allocation, on any input;
  - anything ACCEPTED re-marshals to byte-identical bytes. That is what makes the
    authenticated header trustworthy: the associated data is computed from the
    parsed fields, so if two different byte strings could parse to the same
    envelope, an attacker could alter the bytes on the wire without altering the
    AAD. Requiring the round trip removes the whole class.

A parse failure is a perfectly good outcome here; the test only insists that
success means something exact.
*/
func FuzzUnmarshal(f *testing.F) {
	// Seeds: a real envelope, and shapes that probe the edges of the decoder.
	if wire, err := sealedFixture(); err == nil {
		f.Add(wire)
		f.Add(wire[:len(wire)/2])              // truncated
		f.Add(append(bytes.Clone(wire), 0x00)) // trailing byte
	}
	for _, seed := range []string{
		"", "\x80", "\x81", "\x85", "\xc0", "\xc1", "\xdf\xff\xff\xff\xff",
		"\x81\xa1v\xa5MKDP1", "\x82\xa1v\xa5MKDP1\xa5suite\xa0",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		env, err := envelope.Unmarshal(raw)
		if err != nil {
			return // refusing malformed input is the expected outcome
		}
		if env == nil {
			t.Fatal("Unmarshal returned no error and no envelope")
		}
		again, merr := env.Marshal()
		if merr != nil {
			t.Fatalf("an accepted envelope must re-marshal: %v", merr)
		}
		if !bytes.Equal(raw, again) {
			t.Fatalf("accepted bytes are not canonical:\n in  %x\n out %x", raw, again)
		}
		// Identifiers are fixed-width by type, so an accepted envelope can never
		// carry a short or overlong one — assert the invariant the AAD relies on.
		if len(env.Header.EphemeralPub) == 0 {
			t.Fatal("an accepted envelope must carry an ephemeral public key")
		}
		if len(env.Nonce) == 0 || len(env.Ciphertext) == 0 {
			t.Fatal("an accepted envelope must carry a nonce and ciphertext")
		}
	})
}

/*
TestDecodeBombIsBounded is the other half of the test plan's fuzzing property:
bounded memory and CPU, not merely "no panic".

Each input here is a handful of bytes that CLAIMS an enormous structure — a
msgpack map32 header announcing four billion entries, a str32 announcing four
gigabytes, two hundred nested maps. A decoder that trusts a length prefix and
pre-allocates turns ten bytes from a stranger into an out-of-memory kill, and
this parser runs on every encrypted message that arrives.

The byte-count limit does not help here: these inputs are tiny. What has to hold
is that the decoder allocates as it reads.
*/
func TestDecodeBombIsBounded(t *testing.T) {
	cases := map[string][]byte{
		"map32 4B entries":   {0xdf, 0xff, 0xff, 0xff, 0xff},
		"array32 4B entries": {0xdd, 0xff, 0xff, 0xff, 0xff},
		"str32 4GB":          {0xdb, 0xff, 0xff, 0xff, 0xff},
		"bin32 4GB":          {0xc6, 0xff, 0xff, 0xff, 0xff},
		"nested maps":        nestedMaps(200),
	}
	for name, raw := range cases {
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = envelope.Unmarshal(raw)
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: Unmarshal did not return within 3s on %d bytes", name, len(raw))
		}
	}
}

func nestedMaps(depth int) []byte {
	out := make([]byte, 0, depth*2)
	for i := 0; i < depth; i++ {
		out = append(out, 0x81, 0xa1, 'a')
	}
	return append(out, 0xc0)
}
