// Package authn implements the provider-neutral authentication adapters.
// Each adapter validates one evidence kind and normalizes the outcome to
// domain.AuthenticationResult. Adapters never decide authorization and
// never consult caller-supplied tenant or principal headers.
package authn

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/synanton/security-provider/internal/port"
)

// Registry dispatches evidence to the configured provider adapter.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]port.AuthenticationProvider
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: map[string]port.AuthenticationProvider{}}
}

// Register adds a provider. Duplicate IDs are rejected.
func (r *Registry) Register(p port.AuthenticationProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.providers[p.ID()]; dup {
		return fmt.Errorf("authn: duplicate provider id %q", p.ID())
	}
	r.providers[p.ID()] = p
	return nil
}

// Get returns the provider by ID.
func (r *Registry) Get(id string) (port.AuthenticationProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

// IDs lists registered provider IDs in no particular order.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.providers))
	for id := range r.providers {
		ids = append(ids, id)
	}
	return ids
}

// Health reports every registered provider.
func (r *Registry) Health(ctx context.Context) []port.ProviderHealth {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]port.ProviderHealth, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.Health(ctx))
	}
	return out
}

// now is a package-level clock hook so tests use fake time.
var now = time.Now
