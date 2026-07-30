/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer

import (
	"context"
	"sync"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"golang.org/x/xerrors"
)

// Service implements mailkey.Service over a Resolver and a Store — both
// interfaces, so a host application supplies its own storage and (for tests) a
// controlled resolver without touching the semantics.
//
// The asynchronous half is the part that needs care. Inbound mail may carry a
// Mail-Key header from anyone, and the spec is explicit that header discovery
// must neither delay delivery nor spawn work per message. So header and DNS
// observations enqueue onto a BOUNDED channel drained by a fixed number of
// workers, and a full queue DROPS the trigger: dropping a discovery hint costs
// nothing (the next send resolves synchronously anyway), while queuing without
// a bound would let a mail flood consume memory and outbound sockets.
type Service struct {
	resolver mailkey.Resolver
	store    mailkey.Store
	now      func() time.Time

	// onError observes background failures, since an async trigger has no
	// caller to return them to. Optional.
	onError func(domain string, err error)
	// onDrop observes triggers dropped by a full queue — the signal that a
	// storm is being shed rather than silently disappearing. Optional.
	onDrop func(domain string)

	queue   chan string
	wg      sync.WaitGroup
	stopped chan struct{}
	once    sync.Once

	// pending coalesces queued domains so one domain occupies one slot no
	// matter how many messages mention it.
	pmu     sync.Mutex
	pending map[string]struct{}
}

var _ mailkey.Service = (*Service)(nil)

// Options configures a Service.
type Options struct {
	// QueueSize bounds outstanding async triggers. Default 256.
	QueueSize int
	// Workers is how many background resolutions may run at once. Default 2 —
	// the resolver has its own global cap; this bounds the queue drain.
	Workers int
	// Now is the clock, for tests.
	Now func() time.Time
	// OnError receives background resolution failures.
	OnError func(domain string, err error)
	// OnDrop receives domains whose trigger was dropped by a full queue.
	OnDrop func(domain string)
}

// NewService builds a Service and starts its workers. Call Close to stop them.
func NewService(r mailkey.Resolver, s mailkey.Store, opts Options) *Service {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 256
	}
	if opts.Workers <= 0 {
		opts.Workers = 2
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	svc := &Service{
		resolver: r, store: s, now: opts.Now,
		onError: opts.OnError, onDrop: opts.OnDrop,
		queue:   make(chan string, opts.QueueSize),
		stopped: make(chan struct{}),
		pending: map[string]struct{}{},
	}
	for range opts.Workers {
		svc.wg.Add(1)
		go svc.worker()
	}
	return svc
}

// Close stops the background workers and waits for in-flight work.
func (s *Service) Close() {
	s.once.Do(func() {
		close(s.stopped)
		s.wg.Wait()
	})
}

func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopped:
			return
		case d := <-s.queue:
			s.pmu.Lock()
			delete(s.pending, d)
			s.pmu.Unlock()
			// A background resolution gets its own bounded context: it must not
			// inherit the lifetime of whatever inbound message triggered it.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if _, err := s.resolve(ctx, d, false); err != nil && s.onError != nil {
				s.onError(d, err)
			}
			cancel()
		}
	}
}

// schedule enqueues a domain for background resolution, coalescing duplicates
// and dropping when the queue is full.
func (s *Service) schedule(domain string) {
	s.pmu.Lock()
	if _, dup := s.pending[domain]; dup {
		s.pmu.Unlock()
		return
	}
	s.pending[domain] = struct{}{}
	s.pmu.Unlock()

	select {
	case s.queue <- domain:
	default:
		// Shed load rather than grow. The hint is lost, not the capability:
		// the next outbound send to this domain resolves synchronously.
		s.pmu.Lock()
		delete(s.pending, domain)
		s.pmu.Unlock()
		if s.onDrop != nil {
			s.onDrop(domain)
		}
	}
}

// ObserveDNS records TXT observations for a domain and schedules resolution if
// the observations suggest the cache is behind. DNS data never becomes the
// effective manifest.
func (s *Service) ObserveDNS(ctx context.Context, domain string, txt []string) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	ads, skipped, err := discovery.ParseDNS(d, txt)
	if err != nil {
		return err
	}
	now := s.now()
	if len(ads) == 0 {
		if len(skipped) > 0 {
			// Something MKDP1-shaped was there but unusable: record it as
			// malformed so an operator can see why nothing happened.
			return s.store.PutObservation(ctx, d, mailkey.Observation{
				Source: mailkey.SourceDNS, ObservedAt: now,
				Status: mailkey.ObservationMalformed, Context: skipped[0].Error(),
			})
		}
		return nil // no MKDP1 records at all: nothing observed, nothing to say
	}
	o := mailkey.Observation{Source: mailkey.SourceDNS, ObservedAt: now}
	if id, consistent := singleID(ads); consistent {
		o.ManifestID, o.HasID = id, true
	} else {
		// Several different valid ids. Recorded as inconsistent and resolved
		// over HTTPS — never arbitrated between.
		o.Status = mailkey.ObservationInconsistent
		o.Context = "several different manifest ids advertised"
	}
	if err := s.store.PutObservation(ctx, d, o); err != nil {
		return err
	}
	return s.scheduleIfBehind(ctx, d)
}

// ObserveHeader records a Mail-Key observation from inbound mail. It never
// blocks on the network and never fails the message: a bad header is recorded
// (or ignored) and delivery continues.
func (s *Service) ObserveHeader(ctx context.Context, headerValue, msgContext string) error {
	ad, err := discovery.ParseHeader(headerValue)
	if err != nil {
		// A malformed header from a stranger is not an error condition for the
		// mail — it is simply not an observation.
		return nil
	}
	o := mailkey.Observation{
		Source: mailkey.SourceHeader, ObservedAt: s.now(), Context: msgContext,
	}
	if ad.HasID {
		o.ManifestID, o.HasID = ad.ManifestID, true
	}
	if err := s.store.PutObservation(ctx, ad.Domain, o); err != nil {
		return err
	}
	return s.scheduleIfBehind(ctx, ad.Domain)
}

// scheduleIfBehind queues a background resolution when the peer's cache does
// not match what was just observed.
func (s *Service) scheduleIfBehind(ctx context.Context, domain string) error {
	p, err := s.store.GetPeer(ctx, domain)
	if err != nil {
		return err
	}
	if need, _ := NeedsRefresh(p, s.now()); need {
		s.schedule(domain)
	}
	return nil
}

// singleID reports the common manifest id of a set of advertisements, and
// whether they agree. Advertisements without an id do not create disagreement;
// two DIFFERENT ids do.
func singleID(ads []mailkey.Advertisement) (mailkey.ManifestID, bool) {
	var id mailkey.ManifestID
	seen := false
	for _, ad := range ads {
		if !ad.HasID {
			continue
		}
		if !seen {
			id, seen = ad.ManifestID, true
			continue
		}
		if ad.ManifestID != id {
			return mailkey.ManifestID{}, false
		}
	}
	return id, seen
}

// AddPeer resolves a domain on an administrator's request. It is the same
// resolution every other source performs — "manual" describes who asked, not a
// separate authority — so a failed attempt leaves an inspectable peer rather
// than installing anything.
func (s *Service) AddPeer(ctx context.Context, domain string) (mailkey.Peer, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return mailkey.Peer{}, err
	}
	if err := s.store.PutObservation(ctx, d, mailkey.Observation{
		Source: mailkey.SourceManual, ObservedAt: s.now(), Status: mailkey.ObservationPending,
	}); err != nil {
		return mailkey.Peer{}, err
	}
	return s.refresh(ctx, d)
}

// Refresh forces authority resolution for a domain. It never prefers a DNS or
// header value: there is one authority, and this asks it.
func (s *Service) Refresh(ctx context.Context, domain string) (mailkey.Peer, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return mailkey.Peer{}, err
	}
	return s.refresh(ctx, d)
}

func (s *Service) refresh(ctx context.Context, d string) (mailkey.Peer, error) {
	_, rerr := s.resolve(ctx, d, true)
	p, err := s.store.GetPeer(ctx, d)
	if err != nil {
		return mailkey.Peer{}, err
	}
	if p == nil {
		return mailkey.Peer{}, xerrors.Errorf("peer %q not found after resolution", d)
	}
	// The peer is returned even when resolution failed: an administrator needs
	// to see the failure ON the record, not only as an error string.
	return *p, rerr
}

// ResolveForEncryption is the outbound path's entry point. It returns a usable
// manifest from cache when there is one, otherwise resolves; when nothing
// usable can be had it returns ErrNoKey, and the CALLER applies policy.
//
// The policy split matters: this function never decides to send plaintext. It
// reports that no key is available, and the peer's Policy (plus the host's
// configuration) decides between holding, failing and sending in the clear —
// so a transient failure cannot silently downgrade a domain that has been
// encrypted before.
func (s *Service) ResolveForEncryption(ctx context.Context, domain string) (mailkey.Result, error) {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return mailkey.Result{}, err
	}
	p, err := s.store.GetPeer(ctx, d)
	if err != nil {
		return mailkey.Result{}, err
	}
	if p != nil && p.Policy == mailkey.PolicyDisabled {
		return mailkey.Result{}, mailkey.ErrDisabled
	}
	now := s.now()
	if rec, ok := Usable(p, now); ok {
		if need, _ := NeedsRefresh(p, now); !need {
			// The common case: a valid cached manifest, no network at all.
			return resultOf(rec, p.Domain)
		}
		// Due for refresh but still usable: try, and fall back to the cache if
		// the authority is unreachable. A working key beats a fresh error.
		if res, rerr := s.resolve(ctx, d, false); rerr == nil {
			return res, nil
		}
		return resultOf(rec, p.Domain)
	}
	res, rerr := s.resolve(ctx, d, false)
	if rerr != nil {
		return mailkey.Result{}, rerr
	}
	return res, nil
}

// Forget removes cached state for a domain.
func (s *Service) Forget(ctx context.Context, domain string) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	return s.store.ForgetPeer(ctx, d)
}

// resolve performs one resolution and records the outcome. force skips the
// "already valid" shortcut; the resolver itself coalesces concurrent calls, so
// two callers racing here cost one request.
func (s *Service) resolve(ctx context.Context, d string, force bool) (mailkey.Result, error) {
	if !force {
		if p, err := s.store.GetPeer(ctx, d); err == nil && p != nil {
			if p.Policy == mailkey.PolicyDisabled {
				return mailkey.Result{}, mailkey.ErrDisabled
			}
			if need, _ := NeedsRefresh(p, s.now()); !need {
				if rec, ok := Usable(p, s.now()); ok {
					return resultOf(rec, d)
				}
			}
		}
	}
	res, err := s.resolver.Resolve(ctx, d)
	if err != nil {
		if ferr := s.store.RecordFailure(ctx, d, err); ferr != nil {
			return mailkey.Result{}, ferr
		}
		return mailkey.Result{}, err
	}
	if err := s.store.InstallManifest(ctx, d, res); err != nil {
		return mailkey.Result{}, err
	}
	return res, nil
}

// resultOf rebuilds a Result from a cached record. The stored canonical bytes
// are the manifest — re-parsing them is how the cache stays honest: a record
// whose bytes no longer parse to its own identifiers is not silently used.
func resultOf(rec mailkey.ManifestRecord, domain string) (mailkey.Result, error) {
	m, err := parseStored(rec.CanonicalBytes, domain)
	if err != nil {
		return mailkey.Result{}, err
	}
	return mailkey.Result{
		Manifest:   m,
		ManifestID: rec.ManifestID,
		Raw:        rec.CanonicalBytes,
		FetchedAt:  rec.FetchedAt,
		ExpiresAt:  rec.ExpiresAt,
		TLSHost:    rec.AuthorityHost,
	}, nil
}
