/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package discovery

import (
	"encoding/base64"

	"github.com/mailnite/mailkey"
	"golang.org/x/xerrors"
)

// encodeID / decodeID are the text encoding of a manifest id in DNS records and
// mail headers: unpadded base64url of the full 32 bytes. Identifiers are never
// truncated on the wire, and padding is not accepted — one encoding, one
// spelling, so a record either round-trips exactly or is malformed.
func encodeID(id mailkey.ManifestID) string {
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func decodeID(s string) (mailkey.ManifestID, error) {
	var out mailkey.ManifestID
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return out, xerrors.Errorf("must be unpadded base64url: %w", err)
	}
	if len(b) != len(out) {
		return out, xerrors.Errorf("must be %d bytes, got %d", len(out), len(b))
	}
	copy(out[:], b)
	return out, nil
}
