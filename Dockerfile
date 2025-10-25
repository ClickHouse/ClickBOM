# hadolint global ignore=DL3047,DL4001
# Multi-stage build for Go application
FROM golang:1.25.3-alpine3.22 AS builder

# Ensure base packages are up-to-date to pick up security fixes before installing build deps
RUN apk update && apk upgrade --available --no-cache

LABEL maintainer="ClickHouse Security Team" \
      description="ClickBOM - SBOM Management Tool" \
      version="2.0.0"

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a \
    -o clickbom \
    ./cmd/clickbom

# External tools stage
FROM alpine:3.19 AS tools

# Install AWS CLI
RUN apk add --no-cache curl unzip && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install

# Install CycloneDX CLI
RUN wget -O /cyclonedx "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.27.2/cyclonedx-linux-x64" && \
    chmod +x /cyclonedx

# Runtime stage - Distroless
FROM gcr.io/distroless/static-debian12:nonroot

LABEL maintainer="ClickHouse Security Team" \
      description="ClickBOM - SBOM Management Tool" \
      version="2.0.0" \
      security.scan="enabled"

# Copy from tools stage
COPY --from=tools /usr/local/aws-cli /usr/local/aws-cli
COPY --from=tools /usr/local/bin/aws /usr/local/bin/aws
COPY --from=tools /cyclonedx /usr/local/bin/cyclonedx

# Copy the binary from builder
COPY --from=builder /build/clickbom /app/clickbom

# Copy license mappings
COPY license-mappings.json /app/license-mappings.json

# Set working directory
WORKDIR /app

# distroless runs as nonroot user by default (UID 65532)
# Set environment
ENV PATH="/usr/local/bin:$PATH" \
    TEMP_DIR="/tmp"

# Run the application
ENTRYPOINT ["/app/clickbom"]
