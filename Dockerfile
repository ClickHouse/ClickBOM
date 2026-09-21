# hadolint global ignore=DL3047,DL4001,DL4006
# Multi-stage build for Go application
FROM golang:1.27.1-alpine3.24 AS builder

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

# External tools stage.
#
# Only the tools the Go binary actually shells out to live here:
#   - cyclonedx (internal/sbom/processing.go: format conversion)
#   - trivy     (internal/sbom/trivy.go: container image SBOM generation)
# The AWS CLI is intentionally NOT installed: every S3 call goes through the
# AWS SDK, and the CLI's glibc build could not even execute on the previous
# distroless/static runtime (no glibc) — it was ~200MB of dead weight.
FROM alpine:3.24 AS tools

# Pinned so image builds are reproducible and do not depend on the
# unauthenticated GitHub "latest release" API (rate-limited, and a failure
# there previously produced an empty version string mid-build). Both downloads
# are SHA-256 verified: this image is rebuilt inside every consumer job, which
# holds production AWS/Mend/Wiz/ClickHouse credentials, so a re-pointed release
# asset must fail the build rather than run. Bump version and hash together.
ARG CYCLONEDX_CLI_VERSION=0.27.2
# sha256 of https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.27.2/cyclonedx-linux-x64
ARG CYCLONEDX_CLI_SHA256=5e1595542a6367378a3944bbd3008caab3de65d572345361d3b9597b1dbbaaa0
ARG TRIVY_VERSION=0.74.0

RUN apk add --no-cache ca-certificates

WORKDIR /tmp/tools

# CycloneDX CLI: a self-contained .NET single-file binary. It is dynamically
# linked against glibc, libgcc and libstdc++, which drives the choice of the
# `cc` distroless runtime below.
RUN wget -qO /cyclonedx "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v${CYCLONEDX_CLI_VERSION}/cyclonedx-linux-x64" && \
    echo "${CYCLONEDX_CLI_SHA256}  /cyclonedx" | sha256sum -c - && \
    chmod +x /cyclonedx

# Trivy: static Go binary, verified against the checksums file published with
# the release.
RUN wget -qO trivy_checksums.txt "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" && \
    wget -qO "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" && \
    grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz$" trivy_checksums.txt | sha256sum -c - && \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm -f trivy_checksums.txt "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"

# Shared libraries the .NET runtime embedded in cyclonedx-cli needs beyond
# what distroless `cc` ships. Sourced from the same Debian release as the
# runtime image so the glibc ABI matches exactly.
#   - libz.so.1 (zlib): loaded at startup by the .NET host; without it
#     cyclonedx fails with "error while loading shared libraries: libz.so.1".
FROM debian:12-slim AS libs

# Runtime stage - Distroless.
#
# `cc-debian12`, NOT `static-debian12`: cyclonedx-cli needs glibc + libgcc +
# libstdc++ at runtime. On `static` (which ships none of them) every
# `cyclonedx convert` failed with
#   fork/exec /usr/local/bin/cyclonedx: no such file or directory
# because the kernel could not find the ELF interpreter /lib64/ld-linux-x86-64.so.2.
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL maintainer="ClickHouse Security Team" \
      description="ClickBOM - SBOM Management Tool" \
      version="2.0.0" \
      security.scan="enabled"

# Copy from tools stage
COPY --from=tools /cyclonedx /usr/local/bin/cyclonedx
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/trivy

# Extra runtime libraries for cyclonedx-cli (see the `libs` stage).
COPY --from=libs /usr/lib/x86_64-linux-gnu/libz.so.1* /usr/lib/x86_64-linux-gnu/

# Copy the binary from builder
COPY --from=builder /build/clickbom /app/clickbom

# Copy license mappings
COPY license-mappings.json /app/license-mappings.json

# Set working directory
WORKDIR /app

# distroless runs as nonroot user by default (UID 65532)
#
# DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1: distroless has no ICU libraries;
# invariant globalization lets the .NET runtime embedded in cyclonedx-cli start
# without them (culture-specific formatting is irrelevant for SBOM conversion).
# DOTNET_BUNDLE_EXTRACT_BASE_DIR: guaranteed-writable scratch location should
# the single-file host need to extract anything at startup.
ENV PATH="/usr/local/bin:$PATH" \
    TEMP_DIR="/tmp" \
    TRIVY_CACHE_DIR="/tmp/.trivy" \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    DOTNET_BUNDLE_EXTRACT_BASE_DIR="/tmp/.net"

# Run the application
ENTRYPOINT ["/app/clickbom"]
