/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

/*
Package component wires MKDP1 into a dependency-injection application built on
go.arpabet.com/glue.

It exists so the protocol packages do not have to. mailkey, manifest, discovery,
resolver and peer depend on nothing but the standard library, value and xerrors —
an integrator using a different container, or none, imports those directly.
Everything DI-shaped lives here: bean names, PostConstruct, injected properties,
lifecycle.

Two beans, both declaring their dependencies as INTERFACES so a host can
substitute either half:

	ResolverBean  builds a hardened resolver from properties
	ServiceBean   builds the peer service over that resolver and the host's Store

The host application supplies exactly one thing MKDP1 cannot supply itself —
storage — by registering any bean that implements mailkey.Store. Everything
else, including every safety default, comes from here.

Settings (all optional, defaults chosen so an unconfigured install is safe):

	mkdp.enabled                            true
	mkdp.resolver.timeout-seconds           8
	mkdp.resolver.max-body-bytes            16384
	mkdp.resolver.max-concurrent            8
	mkdp.resolver.max-manifest-lifetime-hours 720   (30 days)
	mkdp.resolver.max-clock-skew-seconds    300
	mkdp.security.allow-private-targets     false   ← see the warning below
	mkdp.discovery.queue-size               256
	mkdp.discovery.workers                  2
*/
package component

import (
	"context"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/peer"
	"github.com/mailnite/mailkey/resolver"
	"go.arpabet.com/glue"
	"go.uber.org/zap"
)

// Bean names, so a host can inject a specific one by qualifier.
const (
	ResolverBeanName = "mailkey-resolver"
	ServiceBeanName  = "mailkey-service"
)

// ResolverBean is the glue bean for the MKDP1 authority client. It owns no
// state a host needs to reach: the useful surface is the mailkey.Resolver
// interface it satisfies.
type ResolverBean struct {
	Log        *zap.Logger     `inject:""`
	Properties glue.Properties `inject:""`

	resolver *resolver.Resolver
	enabled  bool
}

// NewResolverBean constructs the bean (properties arrive by injection).
func NewResolverBean() *ResolverBean { return &ResolverBean{} }

var (
	_ mailkey.Resolver      = (*ResolverBean)(nil)
	_ glue.NamedBean        = (*ResolverBean)(nil)
	_ glue.InitializingBean = (*ResolverBean)(nil)
)

func (t *ResolverBean) BeanName() string { return ResolverBeanName }

func (t *ResolverBean) PostConstruct() error {
	p := t.Properties
	t.enabled = p.GetBool("mkdp.enabled", true)

	allowPrivate := p.GetBool("mkdp.security.allow-private-targets", false)
	if allowPrivate {
		// Loud on purpose. This is the one setting that widens the anti-SSRF
		// policy, and it exists for split-DNS deployments — an operator who set
		// it by accident should find out from the log, not from an incident.
		t.Log.Warn("MailKeyPrivateTargetsAllowed", zap.String("effect",
			"MKDP1 may resolve authorities on loopback and private addresses; link-local and reserved ranges stay refused"))
	}

	t.resolver = resolver.New(resolver.Options{
		Timeout:      time.Duration(p.GetInt("mkdp.resolver.timeout-seconds", 8)) * time.Second,
		MaxBodyBytes: int64(p.GetInt("mkdp.resolver.max-body-bytes", mailkey.MaxBodyBytes)),
		Limits: manifest.Limits{
			MaxLifetime:  time.Duration(p.GetInt("mkdp.resolver.max-manifest-lifetime-hours", 720)) * time.Hour,
			MaxClockSkew: time.Duration(p.GetInt("mkdp.resolver.max-clock-skew-seconds", 300)) * time.Second,
		},
		AllowPrivateTargets: allowPrivate,
		MaxConcurrent:       p.GetInt("mkdp.resolver.max-concurrent", 8),
		UserAgent:           p.GetString("mkdp.resolver.user-agent", ""),
	})
	t.Log.Info("MailKeyResolver", zap.Bool("enabled", t.enabled),
		zap.Bool("allowPrivateTargets", allowPrivate))
	return nil
}

// Resolve implements mailkey.Resolver. With MKDP1 switched off it reports that
// no key is available rather than resolving — a disabled protocol must not make
// network requests, and the caller's policy decides what "no key" means.
func (t *ResolverBean) Resolve(ctx context.Context, domain string) (mailkey.Result, error) {
	if !t.enabled {
		return mailkey.Result{}, mailkey.ErrDisabled
	}
	return t.resolver.Resolve(ctx, domain)
}

// ServiceBean is the glue bean for the peer service: observations in, validated
// keys out. It injects the resolver and the host's store by INTERFACE, so a
// host may replace either — its own resolver for a test harness, its own
// database for storage — without touching protocol behavior.
type ServiceBean struct {
	Log        *zap.Logger     `inject:""`
	Properties glue.Properties `inject:""`
	// Resolver is the authority client. Injected by interface: the bean above
	// satisfies it, and so does a host's own implementation.
	Resolver mailkey.Resolver `inject:""`
	// Store is the ONLY thing MKDP1 cannot supply itself. A host registers any
	// bean implementing mailkey.Store; when none is registered the in-memory
	// reference store is used, which is correct but not durable — so that case
	// is logged as a warning rather than passing silently.
	Store mailkey.Store `inject:"optional"`

	service *peer.Service
}

func NewServiceBean() *ServiceBean { return &ServiceBean{} }

var (
	_ mailkey.Service       = (*ServiceBean)(nil)
	_ glue.NamedBean        = (*ServiceBean)(nil)
	_ glue.InitializingBean = (*ServiceBean)(nil)
	_ glue.DisposableBean   = (*ServiceBean)(nil)
)

func (t *ServiceBean) BeanName() string { return ServiceBeanName }

func (t *ServiceBean) PostConstruct() error {
	// Reused across an in-place restart: stop the previous generation's workers
	// before starting new ones, or each restart would leak a worker set.
	if t.service != nil {
		t.service.Close()
		t.service = nil
	}
	store := t.Store
	if store == nil {
		t.Log.Warn("MailKeyStoreMissing", zap.String("effect",
			"peer state is kept in memory and lost on restart — register a mailkey.Store bean for a durable pin book"))
		store = peer.NewMemStore(nil)
	}
	p := t.Properties
	t.service = peer.NewService(t.Resolver, store, peer.Options{
		QueueSize: p.GetInt("mkdp.discovery.queue-size", 256),
		Workers:   p.GetInt("mkdp.discovery.workers", 2),
		OnError: func(domain string, err error) {
			// Background resolutions have no caller to return to. The failure
			// CLASS is logged, not just the text, because that is what a
			// reader acts on: "absent" is a domain that simply does not speak
			// MKDP1, "protocol" is an endpoint getting it wrong.
			t.Log.Info("MailKeyResolveFailed", zap.String("domain", domain),
				zap.String("class", string(mailkey.ClassOf(err))), zap.Error(err))
		},
		OnDrop: func(domain string) {
			// Shedding load is normal under a storm and must be visible, since
			// the alternative — an unbounded queue — is the actual failure.
			t.Log.Info("MailKeyDiscoveryDropped", zap.String("domain", domain),
				zap.String("reason", "discovery queue full; the next send to this domain resolves synchronously"))
		},
	})
	return nil
}

func (t *ServiceBean) Destroy() error {
	if t.service != nil {
		t.service.Close()
		t.service = nil
	}
	return nil
}

// The mailkey.Service surface, delegated. Written out rather than embedded so
// the bean's public contract is visible here and cannot change under it when
// the interface grows.

func (t *ServiceBean) ObserveDNS(ctx context.Context, domain string, txt []string) error {
	return t.service.ObserveDNS(ctx, domain, txt)
}

func (t *ServiceBean) ObserveHeader(ctx context.Context, headerValue, msgContext string) error {
	return t.service.ObserveHeader(ctx, headerValue, msgContext)
}

func (t *ServiceBean) AddPeer(ctx context.Context, domain string) (mailkey.Peer, error) {
	return t.service.AddPeer(ctx, domain)
}

func (t *ServiceBean) Refresh(ctx context.Context, domain string) (mailkey.Peer, error) {
	return t.service.Refresh(ctx, domain)
}

func (t *ServiceBean) ResolveForEncryption(ctx context.Context, domain string) (mailkey.Result, error) {
	return t.service.ResolveForEncryption(ctx, domain)
}

func (t *ServiceBean) ResolveAcceptingUnpinned(ctx context.Context, domain string) (mailkey.Result, error) {
	return t.service.ResolveAcceptingUnpinned(ctx, domain)
}

func (t *ServiceBean) Forget(ctx context.Context, domain string) error {
	return t.service.Forget(ctx, domain)
}
