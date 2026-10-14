package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/metadata"
)

var testKey = []byte("middleware-test-key-at-least-32-bytes!")

func issueFor(t *testing.T, tenant, principal string) (string, *HMACVerifier) {
	t.Helper()
	v := &HMACVerifier{Key: testKey, ExpectedIssuer: "test-issuer"}
	token := issueToken(t, v, tenant, principal)
	return token, v
}

func TestHMACVerifyRoundtrip(t *testing.T) {
	token, v := issueFor(t, "tenant:acme", "service:ingestor")
	sc, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sc.TenantID != "tenant:acme" || sc.PrincipalID != "service:ingestor" {
		t.Fatalf("context = %+v", sc)
	}
}

func TestHMACVerifyRejects(t *testing.T) {
	_, v := issueFor(t, "tenant:acme", "service:ingestor")
	other := &HMACVerifier{Key: []byte("different-key-at-least-32-bytes!!!!"), ExpectedIssuer: "test-issuer"}
	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrMissingContext},
		{"garbage", "x.y.z", ErrInvalidContext},
		{"wrong key", mustIssue(t, other), ErrInvalidContext},
	}
	for _, tc := range cases {
		if _, err := v.Verify(context.Background(), tc.token); err == nil {
			t.Errorf("%s accepted", tc.name)
		} else if !isErr(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func isErr(err, want error) bool {
	for err != nil {
		if err == want {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestRequireAuthDerivesTenant(t *testing.T) {
	token, v := issueFor(t, "tenant:acme", "service:ingestor")
	var gotTenant string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotTenant, err = TenantIDFromContext(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant:acme")
	rec := httptest.NewRecorder()
	RequireAuth(v)(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotTenant != "tenant:acme" {
		t.Fatalf("tenant = %q", gotTenant)
	}
}

func TestRequireAuthNegative(t *testing.T) {
	token, v := issueFor(t, "tenant:acme", "service:ingestor")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cases := []struct {
		name    string
		headers map[string]string
		query   string
		want    int
	}{
		{"missing token", nil, "", http.StatusUnauthorized},
		{"bad token", map[string]string{"Authorization": "Bearer garbage"}, "", http.StatusUnauthorized},
		{"forged tenant header", map[string]string{"Authorization": "Bearer " + token, "X-Tenant-ID": "tenant:evil"}, "", http.StatusForbidden},
		{"forged tenant query", map[string]string{"Authorization": "Bearer " + token}, "?tenant_id=tenant:evil", http.StatusForbidden},
		{"unsigned user header", map[string]string{"Authorization": "Bearer " + token, "X-User-ID": "user:mallory"}, "", http.StatusForbidden},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/x"+tc.query, nil)
		for k, val := range tc.headers {
			req.Header.Set(k, val)
		}
		rec := httptest.NewRecorder()
		RequireAuth(v)(next).ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestUnaryServerInterceptor(t *testing.T) {
	token, v := issueFor(t, "tenant:acme", "service:ingestor")
	interceptor := UnaryServerInterceptor(v)
	invoke := func(ctx context.Context) (any, error) {
		return interceptor(ctx, nil, nil, func(ctx context.Context, _ any) (any, error) {
			tenant, err := TenantIDFromContext(ctx)
			if err != nil {
				return nil, err
			}
			return tenant, nil
		})
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	out, err := invoke(ctx)
	if err != nil || out != "tenant:acme" {
		t.Fatalf("valid call: out=%v err=%v", out, err)
	}
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token, "x-tenant-id", "tenant:evil"))
	if _, err := invoke(ctx); err == nil {
		t.Fatal("conflicting tenant metadata accepted")
	}
	if _, err := invoke(context.Background()); err == nil {
		t.Fatal("missing metadata accepted")
	}
}

