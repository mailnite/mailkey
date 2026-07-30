/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer

import (
	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"golang.org/x/xerrors"
)

// parseStored re-parses a cached manifest's canonical bytes. The bytes are the
// manifest — a stored record is never trusted to describe itself, so serving
// from cache re-derives the object from the same bytes a fresh fetch would have
// validated. A record whose bytes no longer parse (a corrupted store, a bug in
// a Store implementation) is refused rather than used.
func parseStored(canonical []byte, domain string) (mailkey.Manifest, error) {
	if len(canonical) == 0 {
		return mailkey.Manifest{}, xerrors.Errorf("cached manifest for %q has no bytes", domain)
	}
	m, err := manifest.ParseCanonical(canonical, domain)
	if err != nil {
		return mailkey.Manifest{}, xerrors.Errorf("cached manifest for %q is unusable: %w", domain, err)
	}
	return m, nil
}
