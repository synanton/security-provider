// Package identity adapts Identity 1.29's principal-resolution contract.
// The Security Provider owns no mapping logic: every answer comes from
// Identity 1.29 or a bounded-freshness cache of its responses. Until the
// Identity 1.29 resolution API is production-ready (joint-plan risk 2),
// mode "stub" serves deterministic dev/test mappings; production runs
// fail closed in stub mode only if explicitly configured for it.
package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
)

// Client resolves authentication results through Identity 1.29.
type Client struct {
	endpoint string
	mode     string
	http     *http.Client
	cache    *cache
	stub     *StubResolver
}

// NewClient builds a resolution client from configuration.
func NewClient(cfg config.IdentityConfig) *Client {
	return &Client{
		endpoint: cfg.Endpoint,
		mode:     cfg.Mode,
		http:     &http.Client{Timeout: cfg.Timeout},
		cache:    newCache(cfg.CacheTTL),
		stub:     NewStubResolver(),
	}
}

// Resolve implements port.IdentityResolver semantics: cached success
// within the bounded TTL, otherwise Identity 1.29, failing closed on any
// ambiguity, outage, or mismatch.
func (c *Client) Resolve(ctx context.Context, result domain.AuthenticationResult, requestedTenant string) (domain.PrincipalResolution, error) {
	key := cacheKey(result, requestedTenant)
	if res, ok := c.cache.get(key); ok {
		return res, nil
	}
	res, err := c.resolveUncached(ctx, result, requestedTenant)
	if err != nil {
		return domain.PrincipalResolution{}, err
	}
	c.cache.set(key, res)
	return res, nil
}

func (c *Client) resolveUncached(ctx context.Context, result domain.AuthenticationResult, requestedTenant string) (domain.PrincipalResolution, error) {
	if c.mode == "stub" {
		return c.stub.Resolve(ctx, result, requestedTenant)
	}
	reqBody, _ := json.Marshal(resolutionRequest{
		Issuer:           result.ExternalIssuer,
		Subject:          result.ExternalSubject,
		RequestedTenant:  requestedTenant,
		IdentityRef:      "",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/resolve", bytes.NewReader(reqBody))
	if err != nil {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: build resolution request: %v", domain.ErrDependencyOutage, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: identity endpoint unreachable: %v", domain.ErrDependencyOutage, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: identity endpoint status %d", domain.ErrDependencyOutage, resp.StatusCode)
	}
	var out resolutionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: decode resolution response: %v", domain.ErrDependencyOutage, err)
	}
	return out.toResolution()
}

type resolutionRequest struct {
	Issuer          string `json:"issuer"`
	Subject         string `json:"subject"`
	RequestedTenant string `json:"requested_tenant,omitempty"`
	IdentityRef     string `json:"identity_ref,omitempty"`
}

type resolutionResponse struct {
	PrincipalID   string `json:"principal_id"`
	PrincipalType string `json:"principal_type"`
	TenantID      string `json:"tenant_id"`
	Active        bool   `json:"active"`
	Ambiguous     bool   `json:"ambiguous"`
	IdentityRef   string `json:"identity_ref"`
}

func (r resolutionResponse) toResolution() (domain.PrincipalResolution, error) {
	if r.Ambiguous {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: identity reports ambiguous mapping (ref %q)", domain.ErrPrincipalAmbiguous, r.IdentityRef)
	}
	if r.PrincipalID == "" {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: identity reports no mapping (ref %q)", domain.ErrPrincipalUnknown, r.IdentityRef)
	}
	if !r.Active {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: principal %q disabled", domain.ErrPrincipalDisabled, r.PrincipalID)
	}
	pt := domain.PrincipalType(r.PrincipalType)
	if !pt.Valid() {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: identity reports unknown principal type %q", domain.ErrPrincipalUnknown, r.PrincipalType)
	}
	return domain.PrincipalResolution{
		PrincipalID:   r.PrincipalID,
		PrincipalType: pt,
		TenantID:      r.TenantID,
		Active:        true,
		IdentityRef:   r.IdentityRef,
	}, nil
}

// StubResolver serves deterministic mappings for development, CI, and
// the D.1 middleware handshake. It encodes no production trust: any entry
// must be an explicit test fixture, and unknown identities fail closed.
type StubResolver struct {
	mu      sync.RWMutex
	entries map[string]domain.PrincipalResolution
}

// NewStubResolver builds an empty stub.
func NewStubResolver() *StubResolver {
	return &StubResolver{entries: map[string]domain.PrincipalResolution{}}
}

// Add registers a fixture: external (issuer, subject) -> resolution.
func (s *StubResolver) Add(issuer, subject string, res domain.PrincipalResolution) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[issuer+"|"+subject] = res
}

// Resolve serves fixtures and fails closed otherwise.
func (s *StubResolver) Resolve(_ context.Context, result domain.AuthenticationResult, requestedTenant string) (domain.PrincipalResolution, error) {
	s.mu.RLock()
	res, ok := s.entries[result.ExternalIssuer+"|"+result.ExternalSubject]
	s.mu.RUnlock()
	if !ok {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: no stub mapping for %q", domain.ErrPrincipalUnknown, result.ExternalSubject)
	}
	if res.Ambiguous {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: stub reports ambiguous mapping", domain.ErrPrincipalAmbiguous)
	}
	if !res.Active {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: principal disabled", domain.ErrPrincipalDisabled)
	}
	if requestedTenant != "" && requestedTenant != res.TenantID {
		return domain.PrincipalResolution{}, fmt.Errorf("%w: requested tenant %q not granted", domain.ErrTenantDenied, requestedTenant)
	}
	return res, nil
}

// cache is a bounded-freshness cache of Identity 1.29 responses. Only
// successes are cached; failures always fail closed and are never cached.
type cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]cacheEntry
}

type cacheEntry struct {
	res domain.PrincipalResolution
	at  time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, entries: map[string]cacheEntry{}}
}

func cacheKey(result domain.AuthenticationResult, tenant string) string {
	return result.ProviderID + "|" + result.ExternalIssuer + "|" + result.ExternalSubject + "|" + tenant
}

func (c *cache) get(key string) (domain.PrincipalResolution, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return domain.PrincipalResolution{}, false
	}
	if time.Since(e.at) > c.ttl {
		delete(c.entries, key)
		return domain.PrincipalResolution{}, false
	}
	return e.res, true
}

func (c *cache) set(key string, res domain.PrincipalResolution) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{res: res, at: time.Now()}
}

// AddStubMapping registers a dev/test fixture on the stub resolver. It
// is a no-op for the mapping itself in http mode; tests use it to drive
// the D.1 middleware handshake without an Identity 1.29 deployment.
func (c *Client) AddStubMapping(issuer, subject string, res domain.PrincipalResolution) {
	c.stub.Add(issuer, subject, res)
}

// Invalidate drops one entry (principal disablement, policy change).
func (c *Client) Invalidate(result domain.AuthenticationResult, requestedTenant string) {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	delete(c.cache.entries, cacheKey(result, requestedTenant))
}
