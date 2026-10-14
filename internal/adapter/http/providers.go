package http

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/synanton/security-provider/internal/port"
)

// ProviderView is the administrative view of a provider. It exposes
// configuration metadata only: never tokens, keys, or credential material.
type ProviderView struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProviderAdmin is the audited, in-memory store behind the provider
// administration endpoints. Durable persistence of provider_configs is a
// Phase 3 concern (owned tables per proposal §10); until then restarts
// reload from the config file.
type ProviderAdmin struct {
	mu    sync.RWMutex
	views map[string]ProviderView
}

// NewProviderAdmin builds an empty admin store.
func NewProviderAdmin() *ProviderAdmin {
	return &ProviderAdmin{views: map[string]ProviderView{}}
}

// Seed registers the statically configured providers.
func (a *ProviderAdmin) Seed(views []ProviderView) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range views {
		a.views[v.ID] = v
	}
}

// SeedProviders registers the statically configured providers for the
// administrative view.
func (s *Server) SeedProviders(views []ProviderView) {
	s.providerAdmin.Seed(views)
}

func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	s.providerAdmin.mu.RLock()
	views := make([]ProviderView, 0, len(s.providerAdmin.views))
	for _, v := range s.providerAdmin.views {
		views = append(views, v)
	}
	s.providerAdmin.mu.RUnlock()
	health := map[string]string{}
	for _, h := range s.registry.Health(r.Context()) {
		if h.Healthy {
			health[h.ProviderID] = "healthy"
		} else {
			health[h.ProviderID] = "unhealthy: " + h.Detail
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": views, "health": health})
}

type registerProviderRequest struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
}

func (s *Server) handleRegisterProvider(w http.ResponseWriter, r *http.Request) {
	s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		var req registerProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.Type == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "id and type are required")
			return
		}
		s.providerAdmin.mu.Lock()
		s.providerAdmin.views[req.ID] = ProviderView{ID: req.ID, Type: req.Type, Enabled: req.Enabled, UpdatedAt: time.Now().UTC()}
		s.providerAdmin.mu.Unlock()
		s.auditor.Record(r.Context(), port.AuditEvent{Type: "provider_register", ProviderID: req.ID, Outcome: "success", ReasonCode: "OK"})
		writeJSON(w, http.StatusCreated, map[string]string{"id": req.ID})
	})(w, r)
}

type patchProviderRequest struct {
	Enabled *bool `json:"enabled"`
}

func (s *Server) handlePatchProvider(w http.ResponseWriter, r *http.Request) {
	s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req patchProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "undecodable request")
			return
		}
		s.providerAdmin.mu.Lock()
		v, ok := s.providerAdmin.views[id]
		if !ok {
			s.providerAdmin.mu.Unlock()
			writeError(w, http.StatusNotFound, "UNKNOWN_PROVIDER", "unknown provider")
			return
		}
		if req.Enabled != nil {
			v.Enabled = *req.Enabled
		}
		v.UpdatedAt = time.Now().UTC()
		s.providerAdmin.views[id] = v
		s.providerAdmin.mu.Unlock()
		s.auditor.Record(r.Context(), port.AuditEvent{Type: "provider_update", ProviderID: id, Outcome: "success", ReasonCode: "OK"})
		writeJSON(w, http.StatusOK, v)
	})(w, r)
}
