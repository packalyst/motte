FROM golang:1.24-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y gcc libc6-dev

WORKDIR /app

# Copy source code
COPY . .

# Download dependencies and build
RUN go mod tidy && \
    CGO_ENABLED=1 go build -o /api ./cmd/main.go

# Final stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iptables \
    wireguard-tools \
    iproute2 \
    dnsutils \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary and configs
COPY --from=builder /api /app/api
COPY configs/ /app/configs/

# Create data directory
RUN mkdir -p /data/firewall /data/wireguard

# No default env vars - all must be set via docker-compose or .env
# Required: CONFIG_PATH, DATA_DIR, API_PORT, etc.

# Expose port (actual port comes from API_PORT env var)
EXPOSE 8080 8081 8082

# Health check (uses API_PORT from environment)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${API_PORT:-8081}/health || exit 1

# Run the API
CMD ["/app/api"]
