MODULE := github.com/synanton/security-provider
GO := go
GOLANGCI := golangci-lint
# Single source of truth for the binary version. Every build path stamps
# from here — make, Docker (--build-arg VERSION=$(cat VERSION)), release
# workflow. Missing file falls back to dev rather than failing the build.
VERSION := $(shell cat VERSION 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-integration vet lint tools clean proto certs docker-up docker-down

build:
	$(GO) build -ldflags "$(LDFLAGS)" ./...

test:
	$(GO) test -race ./...

# Integration suite needs no Docker: mTLS is exercised over httptest with
# in-test certificates (test/integration). Kept behind the build tag so
# plain `go test ./...` stays hermetic.
test-integration:
	$(GO) test -race -tags=integration ./test/integration/... -v

vet:
	$(GO) vet ./...

lint:
	$(GOLANGCI) run ./...

tools:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Regenerate the gRPC stubs from proto/security/v1. Requires buf +
# protoc-gen-go + protoc-gen-go-grpc on PATH.
# Run ONLY when the .proto contract changes — a diff here without an
# accompanying contract change is a regression, not an update.
proto:
	PATH="$$HOME/go/bin:$$PATH" buf lint && PATH="$$HOME/go/bin:$$PATH" buf generate

# Dev-only self-signed certificates for local mTLS smoke runs.
# Output stays in ./certs/ (gitignored). Never use in production;
# production mounts real certificates from the secret store.
certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout certs/service.key -out certs/service.crt \
		-days 30 -subj "/CN=security-provider-dev"
	chmod 600 certs/service.key
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout certs/client-ca.key -out certs/client-ca.crt \
		-days 30 -subj "/CN=security-provider-workload-ca"
	chmod 600 certs/client-ca.key
	ls -l certs/

docker-up: certs
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -rf bin/
