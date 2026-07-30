/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package message

import (
	"bytes"
	"strings"
)

/*
The minimum of RFC 5322 header handling MKDP1 needs, written out rather than
imported.

A protocol library that pulls in a MIME stack to read three fields makes itself
awkward to adopt: the host application already has its own mail parser, and now
has two. Everything here is field-level and unfolding-only — no MIME, no
encodings, no structure beyond "headers, blank line, body" — which is all the
protocol's framing depends on.
*/

// SplitHeaderBody divides a message at the first blank line. The body is
// returned verbatim, including the case where there is none.
func SplitHeaderBody(raw []byte) (header, body []byte) {
	for i, rest := 0, raw; len(rest) > 0; {
		line, tail := nextLine(rest)
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			return raw[:i], tail
		}
		i += len(line)
		rest = tail
	}
	return raw, nil
}

/*
HeaderValue reads a field from a message's header block, unfolding continuation
lines.

It returns the FIRST occurrence. For a field this server writes there is exactly
one (SetHeader replaces); for inbound mail the topmost is the one the last hop
wrote, which is the hop whose claim is being read.
*/
func HeaderValue(raw []byte, name string) string {
	prefix := []byte(strings.ToLower(name) + ":")
	var value []byte
	collecting := false
	rest := raw
	for len(rest) > 0 {
		line, tail := nextLine(rest)
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			break // end of the header block
		}
		switch {
		case collecting && isContinuation(line):
			value = append(value, ' ')
			value = append(value, bytes.TrimSpace(line)...)
		case collecting:
			return string(bytes.TrimSpace(value))
		case bytes.HasPrefix(bytes.ToLower(line), prefix):
			collecting = true
			value = append(value, bytes.TrimSpace(line[len(prefix):])...)
		}
		rest = tail
	}
	return string(bytes.TrimSpace(value))
}

/*
SetHeader replaces every occurrence of a field with one instance carrying value,
prepended to the header block.

Replacing rather than appending matters for one specific reason: DKIM. These
fields are covered by the signature, and RFC 6376 resolves duplicate field names
from the bottom up — so a message that arrived carrying its own Mail-Key would
get one instance signed while a receiver read another. One field, one meaning.

Only the header block is touched. Everything from the first blank line on is
body, including the quoted headers of a forwarded message.
*/
func SetHeader(raw []byte, name, value string) []byte {
	line := []byte(name + ": " + value + "\r\n")
	stripped := RemoveHeader(raw, name)
	out := make([]byte, 0, len(line)+len(stripped))
	return append(append(out, line...), stripped...)
}

// RemoveHeader drops a field and its folded continuation lines from the header
// block.
func RemoveHeader(raw []byte, name string) []byte {
	prefix := []byte(strings.ToLower(name) + ":")
	var out []byte
	rest := raw
	dropping := false
	for len(rest) > 0 {
		line, tail := nextLine(rest)
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			// End of the header block: the body follows verbatim.
			if out == nil {
				return raw // nothing was dropped; avoid a needless copy
			}
			return append(out, rest...)
		}
		if isContinuation(line) {
			if dropping {
				rest = tail
				continue // a folded line of the field being removed
			}
		} else {
			dropping = bytes.HasPrefix(bytes.ToLower(line), prefix)
		}
		if out == nil {
			out = make([]byte, 0, len(raw))
			out = append(out, raw[:len(raw)-len(rest)]...)
		}
		if !dropping {
			out = append(out, line...)
		}
		rest = tail
	}
	if out == nil {
		return raw
	}
	return out
}

// nextLine splits off one line including its terminator.
func nextLine(b []byte) (line, rest []byte) {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i+1], b[i+1:]
	}
	return b, nil
}

// isContinuation reports whether a header line is a folded continuation.
func isContinuation(line []byte) bool {
	return len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
}
