package middleware

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor validates the Bearer context token from the
// authorization metadata, injects it, and cross-checks the x-tenant-id
// metadata hint on mismatch. Stream interceptors follow the same shape
// and are a Phase 3 addition.
func UnaryServerInterceptor(v Verifier) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		var token string
		for _, h := range md.Get("authorization") {
			if t := bearerOf(h); t != "" {
				token = t
				break
			}
		}
		sc, err := v.Verify(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid security context")
		}
		ctx = WithSecurityContext(ctx, sc)
		for _, hint := range md.Get("x-tenant-id") {
			if err := CheckTenantHint(ctx, hint); err != nil {
				return nil, status.Error(codes.PermissionDenied, "conflicting tenant claim")
			}
		}
		return handler(ctx, req)
	}
}

// TokenSource supplies an outgoing context token (issued by the Security
// Provider) for client-side calls.
type TokenSource func(ctx context.Context) string

// UnaryClientInterceptor attaches the context token as authorization
// metadata on every call.
func UnaryClientInterceptor(src TokenSource) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if token := src(ctx); token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// StaticTokenSource returns a TokenSource that always supplies token.
// Prefer short-lived, per-call sources in production.
func StaticTokenSource(token string) TokenSource {
	return func(context.Context) string { return token }
}

// bearerCredentials implements credentials.PerRPCCredentials for static
// context tokens. It requires transport security: refusing to attach
// tokens on insecure channels is the caller's dial concern.
type bearerCredentials struct {
	token string
}

// PerRPCCredentials builds transport credentials carrying the token.
func PerRPCCredentials(token string) credentials.PerRPCCredentials {
	return bearerCredentials{token: token}
}

// GetRequestMetadata implements credentials.PerRPCCredentials.
func (b bearerCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials.
func (b bearerCredentials) RequireTransportSecurity() bool { return true }
