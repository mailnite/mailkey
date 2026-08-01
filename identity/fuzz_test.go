/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package identity_test

import (
	"net/http"
	"testing"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/identity"
)

/*
FuzzReadProof drives the proof parser with arbitrary header values.

This parser reads attacker-controlled input on the one path that decides whether
a domain is authenticated, so it is exactly where the two defects fuzzing has
already found in this repository would live again: F-12 (one value with several
valid base64url spellings) and F-16 (bytes accepted that do not re-encode to
themselves). Hand-written cases cover the shapes I thought of; this covers the
ones I did not.

Two invariants, both cheap to state and both fatal if broken:

  - it never panics, whatever it is handed;
  - anything it ACCEPTS must round-trip — re-emitting the parsed proof must
    produce the exact header values that were parsed. A parser that accepted a
    second spelling would fail this, and a fingerprint with two spellings is a
    pin that intermittently reads as the wrong signer.
*/
func FuzzReadProof(f *testing.F) {
	pk, priv := key(&testing.T{}, 11)
	raw := []byte("manifest bytes")
	sig, _ := identity.SignManifest(priv, "example.com", raw)
	fp, _ := identity.FingerprintOf("example.com", pk)
	good := http.Header{}
	identity.WriteProof(good, &mailkey.Proof{PublicKey: pk, Fingerprint: fp, Signature: sig})

	f.Add(good.Get(mailkey.HeaderIdentity), good.Get(mailkey.HeaderSigner), good.Get(mailkey.HeaderSignature))
	f.Add("", "", "")
	f.Add("ed25519:", "", "")
	f.Add("ed25519:AAAA", "AAAA", "AAAA")
	f.Add("x", "y", "z")

	f.Fuzz(func(t *testing.T, id, signer, signature string) {
		h := http.Header{}
		if id != "" {
			h.Set(mailkey.HeaderIdentity, id)
		}
		if signer != "" {
			h.Set(mailkey.HeaderSigner, signer)
		}
		if signature != "" {
			h.Set(mailkey.HeaderSignature, signature)
		}
		proof, found, err := identity.ReadProof(h)
		if err != nil {
			if found || proof != nil {
				t.Fatalf("an error must not also report a proof: found=%v proof=%v", found, proof)
			}
			return
		}
		if !found {
			if proof != nil {
				t.Fatal("absent must mean nil")
			}
			return
		}
		// Accepted. It must be the canonical spelling of itself.
		back := http.Header{}
		identity.WriteProof(back, proof)
		for _, name := range []string{mailkey.HeaderIdentity, mailkey.HeaderSigner, mailkey.HeaderSignature} {
			if back.Get(name) != h.Get(name) {
				t.Fatalf("%s was accepted as %q but re-emits as %q — one value, two spellings",
					name, h.Get(name), back.Get(name))
			}
		}
	})
}
