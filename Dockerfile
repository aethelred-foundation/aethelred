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
# CGO is REQUIRED: the cosmos/evm EIP-712 fee-payer path calls
# secp256k1.RecoverPubkey / VerifySignature, which the cosmos go-ethereum
# fork gates behind `//go:build !gofuzz && cgo` — there is NO pure-Go
# fallback, so CGO_ENABLED=0 fails to compile (undefined symbols). We
# therefore build with cgo + musl and statically link, which keeps the
# distroless/static runtime (no libc) working.
#
# Multi-arch: build natively per TARGETPLATFORM (buildx emulates the
# non-host arch). We must NOT cross-compile via GOOS/GOARCH here — cgo
# cross-compilation would need a target-arch C toolchain the builder
# image does not carry.
# buildx already runs this stage on $TARGETPLATFORM by default (emulated for
# the non-host arch), so each arch builds natively — which is what cgo needs.
FROM golang:1.25.12-alpine AS builder

# build-base provides the musl gcc toolchain cgo needs; git for VCS stamping.
RUN apk add --no-cache build-base git

WORKDIR /build

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with optimizations and version info. Static musl link so the binary
# runs on the libc-free distroless/static runtime.
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=1 \
    go build \
      -tags production \
      -ldflags="-s -w -linkmode external -extldflags '-static' -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -trimpath \
      -o /build/bin/aethelredd \
      ./cmd/aethelredd/

# ------------------------------------
# Stage 2: Minimal production image
# ------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/aethelred/aethelred"
LABEL org.opencontainers.image.description="Aethelred Validator Node"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy binary
COPY --from=builder /build/bin/aethelredd /usr/bin/aethelredd

# Use non-root user (distroless default)
USER nonroot:nonroot

# Default ports: P2P (26656), RPC (26657), gRPC (9090), REST (1317), Prometheus (26660)
EXPOSE 26656 26657 9090 1317 26660

# Health check via RPC status endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/bin/aethelredd", "status"]

ENTRYPOINT ["/usr/bin/aethelredd"]
CMD ["start"]
