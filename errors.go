/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package mailkey

import (
	"errors"
	"fmt"
)

// FailureClass classifies why a resolution did not produce a manifest. The
// class — not the error text — is what a caller acts on: the right reaction to
// "this domain does not publish a key" is nothing at all, while the right
// reaction to "the endpoint answered 200 with an invalid object" is an alert.
// Callers must never pattern-match error strings to tell those apart.
type FailureClass string

const (
	// FailureNetwork: DNS failure, connection refused, timeout. Transient by
	// assumption — retry with backoff, keep any still-valid cached manifest.
	FailureNetwork FailureClass = "network"
	// FailureTLS: the certificate chain or hostname did not validate. Retry,
	// but surface it: on a domain that used to validate, this is what an
	// interception attempt looks like.
	FailureTLS FailureClass = "tls"
	// FailureAbsent: the endpoint answered 404/410. A definitive negative —
	// the domain simply does not speak MKDP1. Not an error condition, and not
	// something to retry hard.
	FailureAbsent FailureClass = "absent"
	// FailureHTTP: any other status, or an unusable response shape.
	FailureHTTP FailureClass = "http"
	// FailureProtocol: a 200 response whose body is not a valid MKDP1
	// manifest — noncanonical bytes, wrong domain, kid mismatch, expired,
	// unknown suite. The alarming class: something is serving the endpoint
	// and getting the protocol wrong.
	FailureProtocol FailureClass = "protocol"
	// FailurePolicy: refused by our own rules before or during the request —
	// an unusable domain, a redirect, a destination address outside the
	// permitted ranges. Never a remote party's fault to fix.
	FailurePolicy FailureClass = "policy"
)

// Error is a classified resolution failure.
type Error struct {
	Class  FailureClass
	Domain string
	Err    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("mailkey %s: %s: %v", e.Class, e.Domain, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Failf builds a classified error.
func Failf(class FailureClass, domain string, format string, args ...any) *Error {
	return &Error{Class: class, Domain: domain, Err: fmt.Errorf(format, args...)}
}

// Fail wraps an existing error with a class.
func Fail(class FailureClass, domain string, err error) *Error {
	return &Error{Class: class, Domain: domain, Err: err}
}

// ClassOf reports the failure class of an error, or "" when it carries none.
func ClassOf(err error) FailureClass {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}

// Sentinels for conditions a caller decides policy on.
var (
	// ErrNoKey: no usable manifest is available for the domain. The outbound
	// path turns this into hold, fail or plaintext according to the peer's
	// policy — never silently into plaintext for a peer that once validated.
	ErrNoKey = errors.New("mailkey: no usable manifest for this domain")
	// ErrDisabled: an administrator disabled MKDP1 for the domain.
	ErrDisabled = errors.New("mailkey: MKDP1 is disabled for this domain")
	// ErrKidRebind: an attempt to map an existing kid to a different key
	// descriptor. A critical integrity error, never an update.
	ErrKidRebind = errors.New("mailkey: kid is already bound to a different key")
)
