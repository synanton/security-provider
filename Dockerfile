# Security Provider — multi-stage, static binary on distroless.
#
# Build: docker build --build-arg VERSION=$(cat VERSION) .
# (VERSION file is the source of truth — never git-describe here; a
# dirty tree or a tarball build would stamp irreproducibly.)
# Run:
#   docker run --rm -p 8080:8080 -p 9090:9090 \
#     -v ./configs/dev.yaml:/etc/security-provider/config.yaml:ro \
#     -v ./certs:/certs:ro \
#     security-provider
#
# Base choice (pinned by scope): distroless/static:nonroot — CA certs
# included (scratch lacks them), no shell to exploit, standard non-root
# user 65532. No HEALTHCHECK shell available, so the healthcheck
# subcommand (same binary) serves docker --health-cmd and k8s probes.
#
# Health signal (pinned): the HEALTHCHECK default path is /health/ready —
# a readiness proxy for Docker/Swarm users. k8s users ignore HEALTHCHECK
# entirely and use livenessProbe: /health/live + readinessProbe:
# /health/ready. /health/live stays 200 through shutdown drain by
# construction (liveness must not restart a deliberately-draining pod).

ARG GO_VERSION=1.23

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
	-ldflags "-s -w -X main.version=${VERSION}" \
	-o /out/security-provider ./cmd/security-provider

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/security-provider /security-provider
# Non-root is the image default (65532); stated explicitly so a base
# change that drops it fails review, not silently runs as root.
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/security-provider"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
	CMD ["/security-provider", "healthcheck"]
