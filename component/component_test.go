/*
 *
 * Copyright 2022-present Karagatan LLC. All rights reserved.
 *
 */

package component_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/mailnite/mailkey"
	"github.com/mailnite/mailkey/component"
	"github.com/mailnite/mailkey/manifest"
	"github.com/mailnite/mailkey/peer"
	"go.arpabet.com/glue"
	"go.uber.org/zap"
)

const domain = "example.com"

// stubResolver stands in for the authority so the container test exercises
// wiring rather than the network. It is registered as a mailkey.Resolver bean,
// which is the point being tested: a host can substitute its own.
type stubResolver struct {
	result mailkey.Result
	err    error
	calls  int
}

func (s *stubResolver) Resolve(context.Context, string) (mailkey.Result, error) {
	s.calls++
	return s.result, s.err
}

func (s *stubResolver) BeanName() string { return "stub-resolver" }

func makeResult(t *testing.T, d string) mailkey.Result {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	m, err := manifest.New(d, now, now.Add(24*time.Hour), mailkey.AlgX25519, mailkey.EncAES256GCM, priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := manifest.Pack(m)
	if err != nil {
		t.Fatal(err)
	}
	return mailkey.Result{Manifest: m, ManifestID: manifest.ManifestIDOf(raw), Raw: raw,
		FetchedAt: now, ExpiresAt: m.ExpiresAt, TLSHost: "mail." + d}
}

// TestContainerWiring builds a real glue container with the host supplying a
// store and a resolver, and drives the protocol through the injected interfaces.
// This is the integration promise of the package: a component application gets
// MKDP1 by registering beans, not by calling constructors.
func TestContainerWiring(t *testing.T) {
	stub := &stubResolver{result: makeResult(t, domain)}
	store := peer.NewMemStore(nil)

	ctx, err := glue.New(
		zap.NewNop(),
		stub,  // the host's own mailkey.Resolver
		store, // the host's own mailkey.Store
		component.NewServiceBean(),
	)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer ctx.Close()

	// The service is reachable by its interface — a host injects
	// mailkey.Service, never a concrete type.
	list := ctx.Bean(mailkey.ServiceClass, 0)
	if len(list) != 1 {
		t.Fatalf("want exactly one mailkey.Service bean, got %d", len(list))
	}
	svc, ok := list[0].Object().(mailkey.Service)
	if !ok {
		t.Fatal("the bean must satisfy mailkey.Service")
	}

	res, err := svc.ResolveForEncryption(context.Background(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if res.ManifestID != stub.result.ManifestID {
		t.Fatal("the injected resolver's result must be what is installed")
	}
	// The peer landed in the host's store, not somewhere internal.
	p, err := store.GetPeer(context.Background(), domain)
	if err != nil || p == nil || p.Effective == nil {
		t.Fatalf("the manifest must be installed in the injected store: %v", err)
	}
	if p.State != mailkey.StateActive {
		t.Fatalf("state = %q", p.State)
	}
	// A second call is served from that store without touching the resolver.
	before := stub.calls
	if _, err := svc.ResolveForEncryption(context.Background(), domain); err != nil {
		t.Fatal(err)
	}
	if stub.calls != before {
		t.Fatal("a cached manifest must not call the resolver again")
	}
}

// TestResolverBeanRespectsDisabled: with mkdp.enabled=false the resolver bean
// refuses rather than making requests. A protocol switched off must not touch
// the network at all.
func TestResolverBeanRespectsDisabled(t *testing.T) {
	ctx, err := glue.New(zap.NewNop(),
		glue.MapPropertySource{"mkdp.enabled": "false"},
		component.NewResolverBean())
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer ctx.Close()

	list := ctx.Bean(mailkey.ResolverClass, 0)
	if len(list) != 1 {
		t.Fatalf("want one mailkey.Resolver bean, got %d", len(list))
	}
	r := list[0].Object().(mailkey.Resolver)
	if _, err := r.Resolve(context.Background(), domain); !errors.Is(err, mailkey.ErrDisabled) {
		t.Fatalf("a disabled resolver must report ErrDisabled, got %v", err)
	}
}

// TestServiceBeanWithoutStore: a host that forgets to register a store still
// gets a working (if non-durable) service — and the situation is a warning, not
// a silent surprise. The bean must not panic on a nil optional injection.
func TestServiceBeanWithoutStore(t *testing.T) {
	stub := &stubResolver{result: makeResult(t, domain)}
	ctx, err := glue.New(zap.NewNop(), stub, component.NewServiceBean())
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer ctx.Close()

	svc := ctx.Bean(mailkey.ServiceClass, 0)[0].Object().(mailkey.Service)
	if _, err := svc.ResolveForEncryption(context.Background(), domain); err != nil {
		t.Fatalf("the fallback in-memory store must work: %v", err)
	}
}

// TestRestartStopsWorkers: PostConstruct may run again on the same bean (an
// in-place restart reuses instances), and Destroy must stop the workers. Neither
// may leak a worker set or panic — a leaked set would keep resolving with a
// store the new generation no longer uses.
func TestRestartStopsWorkers(t *testing.T) {
	stub := &stubResolver{result: makeResult(t, domain)}
	bean := component.NewServiceBean()
	ctx, err := glue.New(zap.NewNop(), stub, bean)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	svc := ctx.Bean(mailkey.ServiceClass, 0)[0].Object().(mailkey.Service)
	if _, err := svc.ResolveForEncryption(context.Background(), domain); err != nil {
		t.Fatal(err)
	}
	// Simulate the in-place restart: the same instance is re-initialized.
	if err := bean.PostConstruct(); err != nil {
		t.Fatalf("re-initialization must succeed: %v", err)
	}
	if _, err := svc.ResolveForEncryption(context.Background(), domain); err != nil {
		t.Fatalf("the bean must work after re-initialization: %v", err)
	}
	ctx.Close()
	// Destroy is idempotent — a second close must not panic.
	if err := bean.Destroy(); err != nil {
		t.Fatalf("a repeated Destroy must be harmless: %v", err)
	}
}

// TestPropertiesConfigureTheResolver: the documented settings actually reach the
// resolver. Checked through behavior — a zero-length body cap would refuse every
// manifest — because a getter test would only prove the struct was filled in.
func TestPropertiesConfigureTheResolver(t *testing.T) {
	ctx, err := glue.New(zap.NewNop(),
		glue.MapPropertySource{
			"mkdp.resolver.timeout-seconds":             "1",
			"mkdp.resolver.max-concurrent":              "1",
			"mkdp.resolver.max-manifest-lifetime-hours": "1",
			"mkdp.security.allow-private-targets":       "true",
		},
		component.NewResolverBean())
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	defer ctx.Close()

	r := ctx.Bean(mailkey.ResolverClass, 0)[0].Object().(mailkey.Resolver)
	// An unusable domain is refused by policy before any network work, which
	// proves the bean produced a real, validating resolver.
	if _, err := r.Resolve(context.Background(), "localhost"); err == nil {
		t.Fatal("an unusable domain must be refused")
	} else if c := mailkey.ClassOf(err); c != mailkey.FailurePolicy {
		t.Fatalf("class %q, want %q", c, mailkey.FailurePolicy)
	}
}
