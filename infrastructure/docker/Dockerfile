# Aethelred Node Dockerfile
# Multi-stage build for optimized image size

# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    gcc \
    musl-dev \
    linux-headers

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN make build

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl \
    jq \
    bash

# Create non-root user
RUN addgroup -S aethelred && adduser -S aethelred -G aethelred

# Copy binary from builder
COPY --from=builder /app/build/aethelredd /usr/local/bin/aethelredd

# Copy initialization scripts
COPY scripts/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set ownership
RUN chown -R aethelred:aethelred /usr/local/bin/aethelredd

# Switch to non-root user
USER aethelred

# Create data directory
RUN mkdir -p /home/aethelred/.aethelred

# Set home directory
WORKDIR /home/aethelred

# Expose ports
# P2P
EXPOSE 26656
# RPC
EXPOSE 26657
# REST API
EXPOSE 1317
# gRPC
EXPOSE 9090
# Prometheus metrics
EXPOSE 26660

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:26657/health || exit 1

# Default command
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["start"]
