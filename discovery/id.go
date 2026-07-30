/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package discovery

import (
	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
)

// encodeID / decodeID are the text encoding of a manifest id in DNS records and
// mail headers: unpadded base64url of the full 32 bytes, in its one canonical
// spelling. Both delegate to the manifest package so the encoding — and the
// canonical-spelling check that goes with it — exists in exactly one place.
func encodeID(id mailkey.ManifestID) string { return manifest.EncodeID(id) }

func decodeID(s string) (mailkey.ManifestID, error) {
	id, err := manifest.DecodeID(s)
	return mailkey.ManifestID(id), err
}
