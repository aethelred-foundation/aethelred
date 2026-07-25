# ============================================================
# Aethelred Validator Node — Production Dockerfile
# ============================================================
# Multi-stage build for a minimal, secure production image.
#
# Usage:
#   docker build -t aethelredd:latest .
#   docker run --rm aethelredd:latest version
# ============================================================

# ------------------------------------
# Stage 1: Build the Go binary
# ------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.25.12-bookworm@sha256:ea341baa9bd5ba6784f6d7161ace70544349a6242d54d34a0fbfd2c4d51c9d58 AS builder

WORKDIR /build

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with optimizations and version info
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -tags production,pqc_circl \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -trimpath \
      -o /build/bin/aethelredd \
      ./cmd/aethelredd/ && \
    mkdir -p /build/runtime-home/.aethelred

# ------------------------------------
# Stage 2: Minimal production image
# ------------------------------------
FROM gcr.io/distroless/static-debian13@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

LABEL org.opencontainers.image.source="https://github.com/aethelred/aethelred"
LABEL org.opencontainers.image.description="Aethelred Validator Node"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy binary
COPY --from=builder /build/bin/aethelredd /usr/bin/aethelredd
COPY --from=builder --chown=65532:65532 /build/runtime-home /home/nonroot

# Use non-root user (distroless default)
USER 65532:65532
ENV HOME=/home/nonroot
WORKDIR /home/nonroot

# Default ports: P2P (26656), RPC (26657), gRPC (9090), REST (1317), Prometheus (26660)
EXPOSE 26656 26657 9090 1317 26660

# Health check via RPC status endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/bin/aethelredd", "status"]

ENTRYPOINT ["/usr/bin/aethelredd"]
CMD ["start"]
