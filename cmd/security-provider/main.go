// Command security-provider is the Synanton Security Provider service:
// the authentication boundary and identity-context producer for the
// platform. See README.md and docs/proposal.md.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	securityv1 "github.com/synanton/security-provider/gen/security/v1"
	"github.com/synanton/security-provider/internal/audit"
	"github.com/synanton/security-provider/internal/authn"
	ctxpkg "github.com/synanton/security-provider/internal/context"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/config"
	grpchandler "github.com/synanton/security-provider/internal/adapter/grpc"
	httphandler "github.com/synanton/security-provider/internal/adapter/http"
	"github.com/synanton/security-provider/internal/identity"
	"github.com/synanton/security-provider/internal/observability"
	"github.com/synanton/security-provider/internal/port"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(os.Args[2:]))
	}
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("security-provider: %v", err)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("security-provider", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML config file (optional; env overrides apply)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levelFor(cfg.LogLevel)}))
	slog.SetDefault(logger)

	registry := authn.NewRegistry()
	views := []httphandler.ProviderView{}
	for _, pc := range cfg.Providers {
		if !pc.Enabled {
			continue
		}
		p, err := buildProvider(pc)
		if err != nil {
			return fmt.Errorf("provider %q: %w", pc.ID, err)
		}
		if err := registry.Register(p); err != nil {
			return err
		}
		views = append(views, httphandler.ProviderView{ID: pc.ID, Type: pc.Type, Enabled: true, UpdatedAt: time.Now().UTC()})
	}

	resolver := identity.NewClient(cfg.Identity)
	for _, m := range cfg.Identity.StubMappings {
		pt := domain.PrincipalType(m.PrincipalType)
		if !pt.Valid() {
			return fmt.Errorf("identity.stub_mappings: unknown principal type %q", m.PrincipalType)
		}
		resolver.AddStubMapping(m.Issuer, m.Subject, domain.PrincipalResolution{
			PrincipalID: m.PrincipalID, PrincipalType: pt,
			TenantID: m.TenantID, Active: true, IdentityRef: "stub",
		})
	}
	issuer, err := buildIssuer(cfg)
	if err != nil {
		return fmt.Errorf("context issuer: %w", err)
	}
	var auditor port.AuditSink
	switch cfg.Audit.Sink {
	case "stdout", "":
		auditor = audit.NewSlogSink()
	case "discard":
		auditor = audit.Discard{}
	default:
		return fmt.Errorf("audit.sink %q unsupported (want stdout|discard)", cfg.Audit.Sink)
	}
	metrics := observability.New(prometheus.DefaultRegisterer.(*prometheus.Registry))

	httpSrv := httphandler.New(registry, resolver, issuer, auditor, metrics, cfg.Server.AdminToken, logger)
	httpSrv.SeedProviders(views)
	handler := httpSrv.Handler()

	httpServer := &http.Server{
		Addr:              cfg.Server.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	tlsCfg, err := serverTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if tlsCfg != nil {
		httpServer.TLSConfig = tlsCfg
	}

	grpcLis, err := net.Listen("tcp", cfg.Server.GRPCAddr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	grpcOpts := []grpc.ServerOption{}
	if tlsCfg != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	grpcSrv := grpc.NewServer(grpcOpts...)
	securityv1.RegisterSecurityProviderServiceServer(grpcSrv, grpchandler.New(registry, resolver, issuer, auditor))
	reflection.Register(grpcSrv)

	logger.Info("security-provider starting", "version", version,
		"http", cfg.Server.HTTPAddr, "grpc", cfg.Server.GRPCAddr,
		"providers", registry.IDs(), "identity_mode", cfg.Identity.Mode)

	errCh := make(chan error, 2)
	go func() {
		var err error
		if tlsCfg != nil {
			err = httpServer.ListenAndServeTLS("", "")
		} else {
			logger.Warn("serving plain HTTP: dev only, never production")
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	go func() {
		if err := grpcSrv.Serve(grpcLis); err != nil {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	case sig := <-sigCh:
		logger.Info("signal received, draining", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		grpcSrv.GracefulStop()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	logger.Info("security-provider stopped")
	return nil
}

func buildProvider(pc config.ProviderConfig) (port.AuthenticationProvider, error) {
	switch pc.Type {
	case "mtls":
		return authn.NewMTLSAdapter(pc)
	case "oidc":
		return authn.NewOIDCAdapter(pc, nil)
	case "workload":
		return authn.NewWorkloadAdapter(pc)
	case "apikey":
		return authn.NewAPIKeyAdapter(pc)
	default:
		return nil, fmt.Errorf("unknown provider type %q", pc.Type)
	}
}

func buildIssuer(cfg *config.Config) (*ctxpkg.Issuer, error) {
	key := []byte(cfg.Server.SigningKey)
	if cfg.Server.SigningKeyFile != "" {
		raw, err := os.ReadFile(cfg.Server.SigningKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read signing key file: %w", err)
		}
		key = raw
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("server.signing_key or server.signing_key_file must be set (min 32 bytes)")
	}
	return ctxpkg.NewIssuer(key, "synanton-security-provider", cfg.Server.ContextTTL)
}

// serverTLSConfig returns nil for plain HTTP (dev only). When a server
// cert is configured, mTLS is enforced iff a client CA is configured.
func serverTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Server.TLS.CertFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.Server.TLS.ClientCA != "" {
		pemBytes, err := os.ReadFile(cfg.Server.TLS.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates parsed from client CA")
		}
		tlsCfg.ClientCAs = pool
		if cfg.Server.TLS.RequireClientCert {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return tlsCfg, nil
}

func levelFor(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
