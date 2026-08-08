/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package peer

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/discovery"
	"github.com/mailnite/mailkey/identity"
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
	// onAlert fires the FIRST time a reviewable condition appears on a domain,
	// and only for the conditions an operator can act on (IssueCode.Alerts).
	// Once per domain per condition, never once per message: the host turns
	// this into a notification, and one that fires on every retry is one that
	// gets dismissed unread. Optional.
	onAlert func(domain string, code mailkey.IssueCode, detail string)

	queue   chan string
	wg      sync.WaitGroup
	stopped chan struct{}
	once    sync.Once

	// pending coalesces queued domains so one domain occupies one slot no
	// matter how many messages mention it.
	pmu     sync.Mutex
	pending map[string]struct{}

	// adm bounds what untrusted observations may turn into durable state. The
	// queue above bounds the network cost of a flood; this bounds the storage
	// cost, which is the half that survives a restart (admission.go).
	adm *admission
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
	// OnAlert receives the first occurrence of an actionable condition on a
	// domain — held mail, a changed signer, a withheld pin, a blocked
	// downgrade. Spec 07 §12 P4: these are worth waking someone for; an
	// unsigned domain is not.
	OnAlert func(domain string, code mailkey.IssueCode, detail string)
	// OnDrop receives domains whose trigger was dropped by a full queue, or
	// whose observation was refused admission.
	OnDrop func(domain string)
	// ObserveInterval coalesces repeated identical observations about one
	// domain: within it, the same evidence is not written again. Default 10m.
	ObserveInterval time.Duration
	// NewPeerBurst and NewPeerEvery bound how fast domains we have never seen
	// may become durable peer records. Defaults: 256 burst, one per ~14s
	// sustained (256/hour). Only FIRST sightings spend budget.
	NewPeerBurst int
	NewPeerEvery time.Duration
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
		onError: opts.OnError, onDrop: opts.OnDrop, onAlert: opts.OnAlert,
		queue:   make(chan string, opts.QueueSize),
		stopped: make(chan struct{}),
		pending: map[string]struct{}{},
		adm:     newAdmission(opts.ObserveInterval, opts.NewPeerBurst, opts.NewPeerEvery, opts.Now()),
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
			if _, err := s.resolve(ctx, d, false, false); err != nil && s.onError != nil {
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
	// The delegated authority, when every record agrees on one. Disagreement
	// leaves it empty (self-hosted): a domain whose records fight about where
	// its manifests live has said nothing usable, and the derived host is the
	// safe reading.
	if a, consistent := singleAuthority(ads); consistent {
		o.Authority = a
	}
	if id, consistent := singleID(ads); consistent {
		o.ManifestID, o.HasID = id, true
	} else {
		// Several different valid ids. Recorded as inconsistent and resolved
		// over HTTPS — never arbitrated between.
		o.Status = mailkey.ObservationInconsistent
		o.Context = "several different manifest ids advertised"
	}
	return s.observe(ctx, d, o)
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
	o.Authority = ad.Authority
	return s.observe(ctx, ad.Domain, o)
}

/*
observe is the admitted write path shared by both observation sources.

Order matters and is the whole point. The in-memory checks come FIRST, so the
common flood — the same domain advertising the same id in message after message
— is answered without reading or writing anything. Only evidence that survives
those touches the store, and only then do we find out whether the domain is new.

A refusal returns nil, never an error: an observation is a hint, ObserveHeader
is called from the inbound path, and failing mail because a stranger's header
arrived too often would turn a rate limit into a denial of service of its own.
*/
func (s *Service) observe(ctx context.Context, domain string, o mailkey.Observation) error {
	now := s.now()
	if !s.adm.allowObservation(domain, o.Source, o.ManifestID, o.HasID, now) {
		return nil // the same evidence, again, within the interval
	}
	p, err := s.store.GetPeer(ctx, domain)
	if err != nil {
		return err
	}
	if p == nil && !s.adm.allowNewPeer(now) {
		// A first sighting with no budget left. Dropped, and visibly so: the
		// domain is discovered by a later message, or resolved synchronously
		// the moment we actually send mail to it.
		if s.onDrop != nil {
			s.onDrop(domain)
		}
		return nil
	}
	if err := s.store.PutObservation(ctx, domain, o); err != nil {
		return err
	}
	return s.scheduleIfBehind(ctx, domain)
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
// singleAuthority is singleID's twin for the a= field: one agreed delegated
// authority across every record, or (false) disagreement. An empty result with
// ok=true is the ordinary self-hosted case.
func singleAuthority(ads []mailkey.Advertisement) (string, bool) {
	a := ""
	seen := false
	for _, ad := range ads {
		if !seen {
			a, seen = ad.Authority, true
			continue
		}
		if ad.Authority != a {
			return "", false
		}
	}
	return a, true
}

// authorityHint reads the delegated authority the freshest observations agreed
// on. It is a ROUTING lookup, deliberately best-effort: a store error or an
// absent record yields "", which resolves against the derived host — the
// pre-delegation behavior.
func (s *Service) authorityHint(ctx context.Context, domain string) string {
	p, err := s.store.GetPeer(ctx, domain)
	if err != nil || p == nil {
		return ""
	}
	newest := time.Time{}
	hint := ""
	for _, o := range p.Observations {
		if o.ObservedAt.After(newest) {
			newest, hint = o.ObservedAt, o.Authority
		}
	}
	return hint
}

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
	// An operator asking for a domain outranks anything admission remembers
	// about it — including a refusal, which must not linger as a reason to
	// ignore the observations that follow.
	s.adm.forget(d)
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
	_, rerr := s.resolve(ctx, d, true, false)
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
/*
ResolveAcceptingUnpinned is ResolveForEncryption for a sender who has been asked
and said yes.

"Proceed" is not one thing (spec 07 §12 P4). Past an IDENTITY refusal it means
encrypting to a manifest that is still WebPKI-authenticated, merely not signed by
the identity we pinned — legacy MKDP1 security, and a defensible choice while a
peer rolls signing out. Past the capability latch it would mean CLEARTEXT to a
domain that has been encrypting for months, and no per-message override may ever
offer that. This function can only do the first: with no key there is nothing for
it to return, so the distinction is structural rather than a check someone must
remember to write.

What it deliberately does NOT do is install the manifest. The pin is unchanged,
the refusal stays on the domain's record, and the next message asks again. An
override is a decision about one message; making it stick would turn a sender in
a hurry into an administrator.
*/
func (s *Service) ResolveAcceptingUnpinned(ctx context.Context, domain string) (mailkey.Result, error) {
	return s.resolveEncrypting(ctx, domain, true)
}

func (s *Service) ResolveForEncryption(ctx context.Context, domain string) (mailkey.Result, error) {
	return s.resolveEncrypting(ctx, domain, false)
}

func (s *Service) resolveEncrypting(ctx context.Context, domain string, acceptUnpinned bool) (mailkey.Result, error) {
	// Normalization is the one failure that stays outside the policy wrapper: a
	// domain we cannot even parse has no peer, no latch and no protection to
	// lose, and holding mail for it would turn a malformed address into stuck
	// mail rather than a bounce.
	d, err := discovery.Normalize(domain)
	if err != nil {
		return mailkey.Result{}, err
	}
	res, p, rerr := s.resolveForEncryption(ctx, d, acceptUnpinned)
	if rerr != nil {
		return mailkey.Result{}, s.policyFailure(ctx, p, d, rerr)
	}
	return res, nil
}

/*
resolveForEncryption is the whole decision, and it is unexported for a reason
that is structural rather than stylistic: it has NO path to the caller.

Every error it produces goes through policyFailure above, because that is the
only way out. That property is what this shape buys, and it was bought the hard
way — the previous version returned from six places, three of which skipped
policy entirely (a store read that failed, a cached manifest whose canonical
bytes would not re-parse, and the refresh fallback). Each looked correct in
isolation, and each was a silent downgrade to plaintext, because the layers above
map any unrecognised error to "no key available" and send in the clear.

Enumerating those exits does not scale — the next edit adds a seventh. Making
them impossible does. A new error path added inside this function is
policy-checked automatically, whether or not whoever adds it has read this
comment.
*/
func (s *Service) resolveForEncryption(ctx context.Context, d string, acceptUnpinned bool) (mailkey.Result, *mailkey.Peer, error) {
	p, err := s.store.GetPeer(ctx, d)
	if err != nil {
		// A store that cannot answer is not evidence that this domain does not
		// encrypt. Passed to policy, which fails closed when it cannot read the
		// latch either.
		return mailkey.Result{}, nil, err
	}
	if p != nil && p.Policy == mailkey.PolicyDisabled {
		// An administrator's decision, not a failure. policyFailure lets
		// ErrDisabled through untouched, so this remains the one deliberate
		// route to cleartext for a known peer.
		return mailkey.Result{}, p, mailkey.ErrDisabled
	}
	now := s.now()
	if rec, ok := Usable(p, now); ok {
		if need, _ := NeedsRefresh(p, now); !need {
			// The common case: a valid cached manifest, no network at all.
			res, cerr := resultOf(rec, p.Domain)
			return res, p, cerr
		}
		// Due for refresh but still usable: try, and fall back to the cache if
		// the authority is unreachable. A working key beats a fresh error.
		if res, rerr := s.resolve(ctx, d, false, acceptUnpinned); rerr == nil {
			return res, p, nil
		}
		res, cerr := resultOf(rec, p.Domain)
		return res, p, cerr
	}
	res, rerr := s.resolve(ctx, d, false, acceptUnpinned)
	return res, p, rerr
}

/*
policyFailure decides whether "no usable key" may become plaintext.

Two things can forbid it, and they are deliberately separate:

  - an administrator asked for encryption to be REQUIRED (PolicyRequire);
  - the domain has already answered over HTTPS at least once, so we KNOW it
    speaks MKDP1 (the capability latch).

The second is the one that closes the silent downgrade. Without it, only
explicitly configured domains are protected, and every automatically discovered
peer — the overwhelming majority — returns to plaintext as soon as its cached
manifest expires and a refresh fails. That is not a hypothetical: an attacker who
can disrupt DNS or the HTTPS path only has to wait for the cache to lapse, and
nothing anywhere reports that the mail went out in the clear. 01-PRD FR-7 and
04-SECURITY §7 forbid it, and this function is where the prohibition lives.

A failure to READ the latch is treated as "the latch is set". The alternative —
falling through to plaintext when the store is unavailable — would make a storage
blip indistinguishable from a domain that never spoke MKDP1, which is the exact
substitution this function exists to prevent.
*/
func (s *Service) policyFailure(ctx context.Context, p *mailkey.Peer, domain string, cause error) error {
	// An administrator's explicit disable is an answer, not a failure: it is the
	// one route to cleartext for a known peer, and wrapping it would make the
	// setting unusable.
	if errors.Is(cause, mailkey.ErrDisabled) {
		return cause
	}
	if p != nil && p.Policy == mailkey.PolicyRequire {
		return mailkey.FailRequired(domain, cause)
	}
	cap, err := s.store.Capability(ctx, domain)
	if err != nil || cap.Requires() {
		return mailkey.FailRequired(domain, cause)
	}
	return cause
}

// Forget removes cached state for a domain.
func (s *Service) Forget(ctx context.Context, domain string) error {
	d, err := discovery.Normalize(domain)
	if err != nil {
		return err
	}
	// Forgetting a peer forgets what admission remembers too: the next
	// observation should be able to rediscover the domain immediately, which is
	// what "not a blocklist" means.
	s.adm.forget(d)
	return s.store.ForgetPeer(ctx, d)
}

// resolve performs one resolution and records the outcome. force skips the
// "already valid" shortcut; the resolver itself coalesces concurrent calls, so
// two callers racing here cost one request.
func (s *Service) resolve(ctx context.Context, d string, force, acceptUnpinned bool) (mailkey.Result, error) {
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
	res, err := s.resolver.Resolve(ctx, d, s.authorityHint(ctx, d))
	if err != nil {
		if ferr := s.store.RecordFailure(ctx, d, err); ferr != nil {
			return mailkey.Result{}, ferr
		}
		// On the domain's record too, coded and counted — but NOT alerted: an
		// unreachable authority is ordinary internet weather, and there is
		// nothing an operator here can do about someone else's outage.
		// IssueRefreshFailed.Alerts() is false, so raise records and stays
		// quiet. Visible on review, silent in the bell.
		s.raise(ctx, d, mailkey.IssueRefreshFailed, err.Error())
		return mailkey.Result{}, err
	}
	/*
		The trust decision comes BEFORE the manifest is allowed to become cached
		state, and the order is the security property.

		Install first and a refused manifest is in the cache; the very next send
		finds it Usable, serves it without another fetch, and the decision that
		refused it is never consulted again. The check would then protect only
		the first message after a takeover.

		So: decide, record what we learned either way, and install only what we
		accepted.
	*/
	prev, _ := s.store.GetPeer(ctx, d)
	verdict := s.decide(prev, res)
	if err := s.store.SetIdentity(ctx, d, ApplyIdentity(identityOf(prev), verdict, res, s.now())); err != nil && s.onError != nil {
		s.onError(d, xerrors.Errorf("identity state: %w", err))
	}
	// The domain answered over HTTPS. Latched even when the identity is refused:
	// the claim is about the transport, and a refusal must never become the
	// reason a later outage sends plaintext.
	if err := s.store.MarkValidated(ctx, d, res.FetchedAt); err != nil && s.onError != nil {
		s.onError(d, xerrors.Errorf("capability latch: %w", err))
	}
	if !verdict.AcceptFetched {
		/*
			A pinned domain answering under a DIFFERENT valid identity is the one
			refusal the published history can settle: a legitimate rotation left
			a signed old→new transition behind (§5), and walking it from OUR pin
			turns "stranger" into "successor" with no human involved. That walk
			happens here — before the refusal is recorded — because its success
			is not a refusal at all.

			Every other refusal reason stays a refusal. A chain cannot excuse a
			missing proof or a replay; it can only explain a signer change.
		*/
		if verdict.Reason == "pinned/valid-proof-other-signer" {
			if res2, ok := s.followRotation(ctx, d, prev, res); ok {
				return res2, nil
			}
		}
		if ferr := s.store.RecordFailure(ctx, d, xerrors.New(verdict.Alert)); ferr != nil && s.onError != nil {
			s.onError(d, ferr)
		}
		// The refusal goes on the DOMAIN's record, coded, because that is where
		// an operator will look for it and because the same refusal repeats on
		// every send until somebody acts.
		s.raise(ctx, d, issueOf(verdict.Reason), verdict.Alert)
		if s.onError != nil {
			s.onError(d, xerrors.Errorf("identity refused (%s): %s", verdict.Reason, verdict.Alert))
		}
		// Encrypt=true on a refusal means the previously accepted manifest is
		// still usable — never that this response passed the identity check. Return
		// that exact cached object and leave the refusal recorded. Conflating these
		// two decisions used to install a stripped or differently signed response
		// during the ordinary refresh window.
		if verdict.Encrypt {
			if rec, ok := Usable(prev, s.now()); ok {
				return resultOf(rec, d)
			}
			// DecideIdentity received cachedUsable from this same peer snapshot, so
			// reaching here means the cache became unusable during this call. Hold
			// rather than falling through to the refused response.
			return mailkey.Result{}, mailkey.FailRequired(d,
				xerrors.New("the trusted cached manifest became unusable while refusing a fresh identity"))
		}
		if acceptUnpinned && overridable(verdict.Reason, res) {
			/*
				The sender was asked and said yes.

				This returns a manifest that is WebPKI-authenticated and NOT
				installed: the pin is untouched, the issue stays on the domain's
				record, and the next message asks again. An override is a
				decision about one message, and letting it stick would turn a
				sender in a hurry into an administrator.
			*/
			return res, nil
		}
		// Wrapped with the narrower sentinel under the SAME predicate, so what a
		// surface is allowed to offer and what this function is willing to do
		// can never drift apart. Before they shared one rule, a replayed
		// manifest was wrapped as an identity refusal and would have been
		// offered to a sender as "send anyway".
		cause := xerrors.New(verdict.Alert)
		if overridable(verdict.Reason, res) {
			cause = xerrors.Errorf("%w: %s", mailkey.ErrIdentityRefused, verdict.Alert)
		}
		return mailkey.Result{}, mailkey.FailRequired(d, cause)
	}
	if err := s.store.InstallManifest(ctx, d, res); err != nil {
		return mailkey.Result{}, err
	}
	// The domain resolved and its identity was accepted, so whatever was wrong
	// with it no longer is. Clearing matters as much as recording: a stale row
	// makes the review list a graveyard, and a condition that recurs after a
	// clear is reported as news rather than folded into a months-old count.
	for _, c := range []mailkey.IssueCode{
		mailkey.IssueSignerChanged, mailkey.IssueProofMissing, mailkey.IssuePinWithheld,
		mailkey.IssueReplay, mailkey.IssueRefreshFailed, mailkey.IssueDowngradeBlocked,
	} {
		if err := s.store.ClearIssue(ctx, d, c); err != nil && s.onError != nil {
			s.onError(d, xerrors.Errorf("clear issue %s: %w", c, err))
		}
	}
	return res, nil
}

/*
followRotation walks a domain's published identity history from OUR pin toward
the signer we just observed.

The rules that make it safe to run unattended:

  - It starts from the LOCAL pin and the LOCALLY STORED public key. A pin
    recorded before the key was kept alongside cannot verify the first link, and
    for such peers the walk declines — the refusal stands and a human decides,
    which is exactly what happened before this function existed.
  - It must ARRIVE at the observed signer. A valid chain ending anywhere else
    explains nothing about the manifest in hand and moves nothing.
  - A REVOKED terminus holds the mail and files IssueRevoked. "This identity was
    withdrawn" is the one thing a chain can say that is worse than "stranger".
  - Success moves the pin THROUGH the store and installs the manifest, so the
    next send takes the ordinary pinned path with no memory of the excursion.
*/
func (s *Service) followRotation(ctx context.Context, d string, prev *mailkey.Peer, res mailkey.Result) (mailkey.Result, bool) {
	cr, ok := s.resolver.(mailkey.IdentityChainResolver)
	if !ok || prev == nil || len(prev.Identity.PinnedPublicKey) == 0 || res.Proof == nil {
		return mailkey.Result{}, false
	}
	raw, err := cr.ResolveIdentityChain(ctx, d)
	if err != nil {
		if s.onError != nil {
			s.onError(d, xerrors.Errorf("identity chain: %w", err))
		}
		return mailkey.Result{}, false
	}
	doc, err := identity.ParseDoc(d, raw)
	if err != nil {
		if s.onError != nil {
			s.onError(d, xerrors.Errorf("identity chain: %w", err))
		}
		return mailkey.Result{}, false
	}
	walk, err := identity.WalkChain(prev.Identity.Fingerprint, prev.Identity.PinnedPublicKey, doc.Chain, s.now())
	if err != nil {
		// A link CLAIMING descent from our pin that does not verify is not a
		// gap in the chain — it is a forgery or corruption, and it is recorded
		// where the operator reviews this domain.
		s.raise(ctx, d, mailkey.IssueSignerChanged, "identity chain did not verify: "+err.Error())
		return mailkey.Result{}, false
	}
	if walk.Revoked {
		s.raise(ctx, d, mailkey.IssueRevoked, "the pinned identity was revoked: "+walk.Reason)
		return mailkey.Result{}, false
	}
	if walk.Applied == 0 || walk.Fingerprint != res.Proof.Fingerprint {
		// The history never reaches the signer we observed. Whatever this is,
		// it is not the rotation it would need to be.
		return mailkey.Result{}, false
	}
	st := identityOf(prev)
	st.Status = mailkey.IdentityPinned
	st.Fingerprint = walk.Fingerprint
	st.PinnedPublicKey = append([]byte(nil), walk.PublicKey...)
	st.PinnedAt = s.now()
	st.Contested = ""
	if !res.Manifest.IssuedAt.IsZero() && res.Manifest.IssuedAt.After(st.LastVerifiedIssuedAt) {
		st.LastVerifiedIssuedAt = res.Manifest.IssuedAt
		st.LastVerifiedManifestID = res.ManifestID
	}
	if err := s.store.SetIdentity(ctx, d, st); err != nil {
		if s.onError != nil {
			s.onError(d, xerrors.Errorf("identity state: %w", err))
		}
		return mailkey.Result{}, false
	}
	if err := s.store.InstallManifest(ctx, d, res); err != nil {
		return mailkey.Result{}, false
	}
	for _, c := range []mailkey.IssueCode{mailkey.IssueSignerChanged, mailkey.IssueProofMissing, mailkey.IssueMailHeld} {
		if cerr := s.store.ClearIssue(ctx, d, c); cerr != nil && s.onError != nil {
			s.onError(d, cerr)
		}
	}
	if s.onError != nil {
		// Informational by design: the operator sees the rotation in the log,
		// but nobody is woken for a transition the OLD key itself authorized.
		s.onError(d, xerrors.Errorf("identity rotated: pin moved to %s by a signed transition", encodeFP(walk.Fingerprint)))
	}
	return res, true
}

/*
raise records one reviewable condition and tells the operator the FIRST time it
happens, and only then.

The store decides "first" under its own lock, because two concurrent sends to a
newly broken domain must not both conclude they were first and both alert. This
function's whole job is to make sure nothing else is tempted to compute it.
*/
func (s *Service) raise(ctx context.Context, domain string, code mailkey.IssueCode, detail string) {
	first, err := s.store.RecordIssue(ctx, domain, code, detail)
	if err != nil {
		if s.onError != nil {
			s.onError(domain, xerrors.Errorf("record issue %s: %w", code, err))
		}
		return
	}
	if first && code.Alerts() && s.onAlert != nil {
		s.onAlert(domain, code, detail)
	}
}

/*
overridable reports whether a refusal may be proceeded past by a sender who
explicitly accepts an unpinned identity.

Two conditions, and each rules out a different disaster.

A PROOF must exist. Without one there is no WebPKI-authenticated manifest to
encrypt to, so "proceed" could only mean cleartext — which the capability latch
exists to forbid and which no per-message override may offer.

And the refusal must not be a REPLAY. A replayed manifest is a real, validly
signed one; that is what makes it dangerous. It names a key we have already
superseded, quite possibly because it was compromised, and an attacker who can
serve it only needs the sender to click "send anyway" once. A pin disagreement is
a question a human can reasonably answer; a rollback is not.
*/
func overridable(reason string, res mailkey.Result) bool {
	return res.Proof != nil && !strings.HasPrefix(reason, "replay/")
}

/*
issueOf maps an identity verdict's matrix row to the condition an operator
reviews.

The verdict's Reason is already a stable identifier — "the matrix row that
produced this verdict" — so this is a translation between two enumerations, not
a parse of prose. The default is the withheld pin rather than something
alarming: an unrecognised refusal means this build met a matrix row it does not
know, and inventing "your authority was compromised" from that would be worse
than saying trust was not established.
*/
func issueOf(reason string) mailkey.IssueCode {
	switch {
	case strings.HasPrefix(reason, "replay/"):
		return mailkey.IssueReplay
	case reason == "pinned/valid-proof-other-signer":
		return mailkey.IssueSignerChanged
	case reason == "pinned/proof-absent-or-invalid":
		return mailkey.IssueProofMissing
	default:
		return mailkey.IssuePinWithheld
	}
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

// decide applies the §6.2 matrix to a fresh fetch, reading the DNS corroboration
// and the cache state from the peer we already hold.
func (s *Service) decide(p *mailkey.Peer, res mailkey.Result) Verdict {
	var dnsFP mailkey.Fingerprint
	var hasDNS, cachedUsable bool
	if p != nil {
		dnsFP, hasDNS = p.Identity.DNSFingerprint, p.Identity.HasDNSFP
		_, cachedUsable = Usable(p, s.now())
	}
	return DecideIdentity(p, res, dnsFP, hasDNS, cachedUsable)
}

func identityOf(p *mailkey.Peer) mailkey.IdentityState {
	if p == nil {
		return mailkey.IdentityState{}
	}
	return p.Identity
}
