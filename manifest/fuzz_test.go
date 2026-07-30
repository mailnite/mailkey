/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package manifest_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
)

// FuzzParseCanonical feeds arbitrary bytes to the parser that reads an
// attacker-controlled endpoint's response. The properties asserted are the ones
// that make the parser safe to point at the internet:
//
//	no panic on any input;
//	anything ACCEPTED repacks to exactly the bytes that were accepted;
//	anything accepted carries a kid that recomputes from its own key.
//
// The second property is the load-bearing one: it means acceptance implies
// canonicality, so a manifest id computed over received bytes is an identity
// nobody can produce two spellings of.
func FuzzParseCanonical(f *testing.F) {
	valid, err := manifest.Pack(mustManifest(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x80})                  // empty map
	f.Add([]byte{0x85})                  // map header promising five entries
	f.Add(append([]byte(nil), valid...)) // the valid object again
	f.Add(append(valid[:len(valid)-1:len(valid)-1], 0xff))
	f.Add([]byte("not messagepack at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := manifest.ParseCanonical(data, "example.com")
		if err != nil {
			return // refusal is always an acceptable outcome
		}
		// Accepted: the object must be exactly what we would have produced.
		repacked, perr := manifest.Pack(m)
		if perr != nil {
			t.Fatalf("an accepted manifest must repack: %v", perr)
		}
		if !bytes.Equal(repacked, data) {
			t.Fatalf("accepted noncanonical bytes:\ninput    %x\nrepacked %x", data, repacked)
		}
		// Accepted: the kid must belong to the key it names.
		kid, kerr := manifest.KeyIDOf(m.Domain, m.Key.Algorithm, m.Key.Encryption, m.Key.PublicKey)
		if kerr != nil {
			t.Fatalf("an accepted manifest must have a computable kid: %v", kerr)
		}
		if kid != m.Key.Kid {
			t.Fatal("an accepted manifest must carry the kid of its own key")
		}
		// Accepted: the domain must be the one requested.
		if m.Domain != "example.com" {
			t.Fatalf("the requested domain must be pinned, got %q", m.Domain)
		}
	})
}

// FuzzDecodeID checks the identifier text parser: no panic, and any accepted
// string re-encodes to itself (one spelling per identifier).
func FuzzDecodeID(f *testing.F) {
	f.Add("")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add(manifest.EncodeID(mustManifest(f).Key.Kid))
	f.Fuzz(func(t *testing.T, s string) {
		id, err := manifest.DecodeID(s)
		if err != nil {
			return
		}
		if got := manifest.EncodeID(id); got != s {
			t.Fatalf("accepted %q but re-encodes to %q", s, got)
		}
	})
}

func mustManifest(f *testing.F) mailkey.Manifest {
	f.Helper()
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	m, err := manifest.New("example.com", time.Unix(1_700_000_000, 0), time.Unix(1_700_086_400, 0),
		mailkey.AlgX25519, mailkey.EncAES256GCM, pk)
	if err != nil {
		f.Fatal(err)
	}
	return m
}
