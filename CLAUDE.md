# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Core Instructions

- Always run tests and/or create new tests for new functionality.
- Always update the documentation (README.md) and CLAUDE.md when necessary.

## What this is

ClickBOM is a Go-based GitHub Action distributed as a Docker container ([action.yml](action.yml), [Dockerfile](Dockerfile)). It downloads SBOMs from GitHub, Mend, Wiz, or generates them from container images via Trivy, normalizes them between CycloneDX and SPDX, optionally merges multiple SBOMs from S3, and uploads results to S3 and/or ClickHouse.

All inputs are passed in through environment variables set by `action.yml` (see [internal/config/config.go](internal/config/config.go)) — there are no CLI flags. The binary entry point is [cmd/clickbom/main.go](cmd/clickbom/main.go).

## Common commands

```bash
# Build the binary
go build -o clickbom ./cmd/clickbom

# Unit tests (matches CI)
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Single test
go test -v -run TestName ./internal/sbom

# Integration tests (build-tagged; require LocalStack S3 + ClickHouse running)
go test -v -tags=integration ./...
#   AWS_ENDPOINT_URL=http://localhost:4566 CLICKHOUSE_URL=http://localhost:8123 \
#   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1

# Lint (CI runs `golangci-lint run --timeout=5m`)
golangci-lint run

# Format check (CI fails if `gofmt -s -l .` produces any output)
gofmt -s -w .

# Build the action's Docker image locally
docker build -t clickbom:test .
```

Go version is pinned to **1.25** in CI ([.github/workflows/tests.yml](.github/workflows/tests.yml)) and in [go.mod](go.mod). Pre-commit hooks ([.pre-commit-config.yaml](.pre-commit-config.yaml)) run `gofmt`, `goimports -local github.com/ClickHouse/ClickBOM`, `go test -short -race`, `go mod tidy`, `gocyclo -over 26`, and `golangci-lint --fix`.

## Architecture

### Execution flow

[main.go](cmd/clickbom/main.go) branches on `cfg.Merge`:

- **Normal mode** (`handleNormalMode`): dispatches on `cfg.SBOMSource` (`github` / `mend` / `wiz` / `trivy`) → download/generate → `ExtractSBOMFromWrapper` (unwraps GitHub's `{"sbom": {...}}` envelope) → `DetectSBOMFormat` (by inspecting `bomFormat` or `spdxVersion`) → `ConvertSBOM` to the requested format → upload to S3 → optionally upload to ClickHouse.
- **Merge mode** (`handleMergeMode`): downloads all objects from the S3 bucket, applies include/exclude glob filters via `ShouldIncludeFile`, keeps only valid CycloneDX files, merges them with `MergeSBOMs`, converts to the desired format, then uploads.

Format conversion shells out to the `cyclonedx` CLI (installed in the Dockerfile). Merging is CycloneDX-only.

### Package layout

- [internal/config](internal/config) — `Config` struct loaded from env vars by `LoadConfig()`. Always calls `Sanitize()` then `Validate()`. Per-source required-field rules live in `Validate()`; do not bypass sanitization, it is the input-trust boundary.
- [internal/validation](internal/validation) — `Sanitize*` helpers (UUIDs, URLs, S3 bucket/key, repository slugs, glob patterns, generic length-capped strings). Hostname allow-listing is enforced by `SanitizeURL(url, kind)` where `kind` selects which hosts are permitted (e.g. `mend`, `wiz`, `clickhouse`).
- [internal/sbom](internal/sbom) — one file per source/concern:
  - `github.go`, `mend.go`, `wiz.go`, `trivy.go` — source clients. Mend uses an async report-export poll loop bounded by `MendMaxWaitTime` / `MendPollInterval`. Trivy supports cross-account ECR via STS `AssumeRole` (`trivy-ecr-role-arn`, optional external ID).
  - `processing.go` — `Format` enum, `DetectSBOMFormat`, `ExtractSBOMFromWrapper`, `ConvertSBOM` (shells out to `cyclonedx convert`).
  - `merge.go` — `MergeSBOMs`, `ExtractSourceReference` (multi-strategy: SPDX doc name → component name → bom-ref → filename).
  - `filter.go` — `filepath.Match` glob filtering for merge mode.
  - `license_mapper.go` + [license-mappings.json](license-mappings.json) — overrides "unknown"/missing licenses by component name. The mapping file is baked into the Docker image at `/app/license-mappings.json`; override with `LICENSE_MAPPING_FILE`.
- [internal/storage](internal/storage) — `S3Client` (AWS SDK v2) and `ClickHouseClient`. ClickHouse uses raw HTTP POST queries (only HTTP is supported — no native protocol). `SetupTable` auto-migrates older tables by adding a `source LowCardinality(String)` column when missing.
- [pkg/logger](pkg/logger) — colorized leveled logger gated by the `DEBUG` env var or `SetDebug(true)`.

### Table-name generation

`generateTableName` ([cmd/clickbom/main.go:277](cmd/clickbom/main.go#L277)) is the contract between SBOM source and ClickHouse: `owner/repo` → `owner_repo`, Mend UUIDs become `mend_<uuid_underscored>`, Wiz/Trivy similar, and merge mode prefixes the sanitized S3 key with `merged_`. Changes here are user-visible (different table per run).

### Runtime image

The Dockerfile is multi-stage and ends on `gcr.io/distroless/static-debian12:nonroot`. The runtime image only contains the static `clickbom` binary plus three external tools copied from a builder: `aws`, `cyclonedx`, `trivy`. Anything that needs to shell out must be one of those three (or added to the tools stage).

## Conventions worth knowing

- `goimports` uses `-local github.com/ClickHouse/ClickBOM`, so internal imports go in their own block.
- Integration tests use `//go:build integration` and are excluded from the default `go test ./...` run. The CI integration job currently has the test step commented out; the tests still exist and can be run locally against LocalStack + ClickHouse.
- Pre-commit blocks direct commits to `main`/`master` and enforces conventional commit messages.
- `gocyclo -over 26` is the hard cyclomatic-complexity ceiling; `handleNormalMode` and `handleMergeMode` are close to it — prefer extracting helpers when adding branches.
