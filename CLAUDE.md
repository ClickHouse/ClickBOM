# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Core Instructions

- Always run tests and/or create new tests for new functionality.
- Always update the documentation (README.md) and CLAUDE.md when necessary.

## What this is

ClickBOM is a Go-based GitHub Action distributed as a Docker container ([action.yml](action.yml), [Dockerfile](Dockerfile)). It downloads SBOMs from GitHub, Mend, Wiz, or generates them from container images via Trivy, normalizes them between CycloneDX and SPDX, optionally merges multiple SBOMs from S3, and uploads results to S3 and/or ClickHouse, optionally posting a success/failure summary of the run to a Slack incoming webhook.

All inputs are passed in through environment variables set by `action.yml` (see [internal/config/config.go](internal/config/config.go)) — there are no CLI flags. The binary entry point is [cmd/clickbom/main.go](cmd/clickbom/main.go).

## Common commands

```bash
# Build the binary
go build -o clickbom ./cmd/clickbom

# Unit tests (matches CI)
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# Single test
go test -v -run TestName ./internal/sbom

# Integration tests (build-tagged; require an S3-compatible store (CI uses RustFS), ClickHouse, and the cyclonedx CLI on PATH)
go test -v -tags=integration ./...
#   docker run -d -p 9000:9000 -e RUSTFS_ACCESS_KEY=minioadmin -e RUSTFS_SECRET_KEY=minioadmin rustfs/rustfs:1.0.0
#   docker run -d -p 8123:8123 -e CLICKHOUSE_USER=clickbom -e CLICKHOUSE_PASSWORD=clickbom clickhouse/clickhouse-server
#   AWS_ENDPOINT_URL=http://localhost:9000 CLICKHOUSE_URL=http://localhost:8123 \
#   CLICKHOUSE_USERNAME=clickbom CLICKHOUSE_PASSWORD=clickbom \
#   AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin AWS_REGION=us-east-1

# Lint (CI runs `golangci-lint run --timeout=5m`)
golangci-lint run

# Format check (CI fails if `gofmt -s -l .` produces any output)
gofmt -s -w .

# Build the action's Docker image locally (amd64 only — the Dockerfile hardcodes GOARCH=amd64 and x64 tool downloads)
docker build --platform linux/amd64 -t clickbom:test .
# Prove the bundled tools can execute in the distroless runtime
docker run --rm --platform linux/amd64 --entrypoint /usr/local/bin/cyclonedx clickbom:test --version
```

[go.mod](go.mod) declares `go 1.25` as the minimum language version; the toolchain actually used is **Go 1.27.1** in both CI ([.github/workflows/tests.yml](.github/workflows/tests.yml), all `setup-go` steps) and the Dockerfile builder (`golang:1.27.1-alpine3.24`). Keep those two in lockstep and on the newest 1.27.x patch: the `test_security` job runs `govulncheck ./...` against that exact toolchain and fails on any reachable stdlib CVE (with 1.26.4 it reported six), which is the intended signal that the shipped binary needs a rebuild. Dependabot bumps the Dockerfile tag; bump `setup-go` in the same PR. (`govulncheck@latest`, x/vuln ≥ 1.8, also refuses to run on anything older than 1.26.) Pre-commit hooks ([.pre-commit-config.yaml](.pre-commit-config.yaml)) run `gofmt`, `goimports -local github.com/ClickHouse/ClickBOM`, `go test -short -race`, `go mod tidy`, `gocyclo -over 26`, and `golangci-lint --fix`.

## Architecture

### Execution flow

`run()` in [main.go](cmd/clickbom/main.go) snapshots `config.SecretsFromEnv()`, loads the config, then calls `execute()` and reports its outcome: when `cfg.SlackWebhookURL` is set, `notifyOutcome` posts one success-or-failure message (bounded by a 2-minute context) built from `notify.RunContextFromEnv()`, `buildSummary(cfg)` (non-sensitive facts only) and `secretsForRedaction(cfg, startupSecrets)`. The run context is the runner's `GITHUB_*` / `RUNNER_OS` default env vars plus `CLICKBOM_JOB_CHECK_RUN_ID`, which action.yml fills from the `job-check-run-id` input whose default is `${{ job.check_run_id }}`: a Docker action's `runs.env` may only reference `inputs`, but input defaults may reference the `job` context, so the id reaches the container without any consumer change. The header links to `{server}/{repo}/actions/runs/{id}/job/{check_run_id}` (verified against the REST API: a job's `html_url` uses its check run id, with no attempt segment) and falls back to `.../runs/{id}[/attempts/{n}]` when the id is empty (older GHES). A notification failure is logged as a warning and never changes the exit status (`notifyOutcome` also recovers a panic without logging its value). `newSlackNotifier` and `notificationTimeout` are package variables so tests can point the notifier at an `httptest` server and shorten the deadline. A `LoadConfig` failure is reported too via `notifyConfigFailure`, which uses `config.SlackWebhookURLFromEnv()` because there is no `Config` to read it from and attaches no summary. `execute()` then branches on `cfg.Merge`:


- **Normal mode** (`handleNormalMode`): dispatches on `cfg.SBOMSource` (`github` / `mend` / `wiz` / `trivy`) → download/generate → `ExtractSBOMFromWrapper` (unwraps the `{"sbom": {...}}` envelope GitHub's deprecated synchronous endpoint used; the asynchronous export returns a bare SPDX document, so for GitHub this is now a pass-through kept for compatibility) → `DetectSBOMFormat` (by inspecting `bomFormat` or `spdxVersion`) → `ConvertSBOM` to the requested format → upload to S3 → optionally upload to ClickHouse.
- **Merge mode** (`handleMergeMode`): downloads all objects from the S3 bucket, applies include/exclude glob filters via `ShouldIncludeFile`, keeps only valid CycloneDX files, merges them with `MergeSBOMs`, converts to the desired format, then uploads.

Format conversion shells out to the `cyclonedx` CLI (installed in the Dockerfile). Merging is CycloneDX-only. `ConvertSBOM` is a plain file copy when the detected input format equals `sbom-format`; the CLI runs only when they differ — GitHub (SPDX in) → `cyclonedx` (the default), or any CycloneDX input (Mend, Wiz, Trivy-cyclonedx, merge output) → `spdxjson`. So a Mend or merge run with the default `sbom-format` never exercises the CLI, and a GitHub run with `sbom-format: spdxjson` doesn't either.

### Package layout

- [internal/config](internal/config) — `Config` struct loaded from env vars by `LoadConfig()`. Always calls `Sanitize()` then `Validate()`. Per-source required-field rules live in `Validate()`; do not bypass sanitization, it is the input-trust boundary.
- [internal/validation](internal/validation) — `Sanitize*` helpers (UUIDs, URLs, S3 bucket/key, repository slugs, glob patterns, generic length-capped strings). Hostname allow-listing is enforced by `SanitizeURL(url, kind)` where `kind` selects which hosts are permitted (e.g. `mend`, `wiz`, `clickhouse`). `SanitizeSlackWebhookURL` is separate on purpose: it accepts only `https://hooks.slack.com/services/...` (or `hooks.slack-gov.com`), fails closed on control characters, credentials, ports, query strings, fragments, `..` and `//`, lower-cases the host, and its error never echoes the value, whereas `SanitizeURL` quotes the URL it rejects. Workflow Builder trigger URLs (`/triggers/`, `/workflows/`) are refused because they take only flat key/value payloads.

- [internal/sbom](internal/sbom) — one file per source/concern:
  - `github.go`, `mend.go`, `wiz.go`, `trivy.go` — source clients. GitHub uses the asynchronous SBOM export: `GET /repos/{owner}/{repo}/dependency-graph/sbom/generate-report` (201, `sbom_url`) → poll `fetch-report/{uuid}` while it answers 202 (`Retry-After`, doubled from 2 s to a 30 s cap) → 302 to a pre-signed blob URL that is fetched by a separate client **without** the GitHub token (the blob store returns 401 if the token is present). The synchronous `GET .../dependency-graph/sbom` endpoint is sunset by GitHub on 2026-11-13 and timed out deterministically on large repositories (`ClickHouse/data-plane-application`, ~25k packages / 52 MB) — do not reintroduce it. Policy: 3 attempts × 30 s back-off around the whole request→poll→download cycle for transient errors (5xx, 429, network, expired report), a 10-minute poll deadline per report, and no retry on permanent errors (401/403/404, an `sbom_url` on a foreign host). The pre-signed URL carries a SAS token, so it is never logged or quoted — `downloadReport` names only the host and `stripURL` unwraps `*url.Error`. `github_test.go` drives the client against an `httptest.NewTLSServer` stub with a fake clock; `github_integration_test.go` (build tag `integration`) hits the real API when `GITHUB_TOKEN` is set (CI passes `github.token`; `GITHUB_SBOM_TEST_REPOSITORY` overrides the target). Mend uses an async report-export poll loop bounded by `MendMaxWaitTime` / `MendPollInterval`; `exportRequest()` picks the endpoint by scope (project → `/projects/{uuid}/dependencies/reports/SBOM`, product → `/applications/{uuid}/dependencies/reports/SBOM` with optional `projectUuids`). Mend API 3.0 has no organization-level dependency SBOM export, so `MEND_ORG_SCOPE_UUID` alone is rejected at validation. Trivy supports cross-account ECR via STS `AssumeRole` (`trivy-ecr-role-arn`, optional `trivy-ecr-external-id`).
  - `processing.go` — `Format` enum, `DetectSBOMFormat`, `ExtractSBOMFromWrapper`, `ConvertSBOM` (shells out to `cyclonedx convert`).
  - `merge.go` — `MergeSBOMs`, `ExtractSourceReference` (multi-strategy: SPDX doc name → component name → bom-ref → filename).
  - `filter.go` — `filepath.Match` glob filtering for merge mode.
  - `license_mapper.go` + [license-mappings.json](license-mappings.json) — overrides "unknown"/missing licenses by component name. The mapping file is baked into the Docker image at `/app/license-mappings.json`; override with `LICENSE_MAPPING_FILE`.
- [internal/notify](internal/notify) — `SlackNotifier` posts an `Event` (run context, non-secret `Summary`, error, duration, redaction list) to a Slack incoming webhook as fallback `text` + a header block carrying the job/run link + one colour-coded `attachment` (fields section, fenced `verbatim` error section, context footer), with `unfurl_links`/`unfurl_media` off. Three attempts with linear back-off, honouring `Retry-After` (seconds or HTTP-date) up to 30 s, retrying only network errors, 429 and 5xx. The client never follows redirects (a 3xx is a permanent failure, so the transport can never forward the credential-bearing URL) and only Slack-style `[A-Za-z0-9_-]` response tokens are quoted (`invalid_payload`, `no_service`, ...), never arbitrary bodies. The webhook URL is a credential: nothing here logs it and `*url.Error` is unwrapped before any error is returned. Error text: first line only, `scrub` (URL userinfo/query strings, bearer and basic auth headers, IP:port socket addresses from `*net.OpError` text, AWS key ids, GitHub tokens, `sig=`/`signature=`/`token=` pairs), then list-based `redact` (each secret, its trailing-slash-trimmed, query-/path-escaped forms and its host with/without port, ASCII-case-insensitively via a byte-wise `replaceFold` rather than a per-needle regexp, which would panic on a binary secret and quote it, longest first, nothing shorter than 4 runes), then a 500-rune cap and code-fence neutralisation; field values are capped at 300 runes. The link is mrkdwn `<url|label>` rather than a Block Kit button because a `url` button still sends an interaction payload that a webhook-only app cannot acknowledge. Env values enter only via `Event` from `cmd/clickbom`: gosec G704 (taint, enforced in CI) fires if `os.Getenv` output reaches `http.Client.Do` inside one package. Unit tests use `httptest` with injected `sleep`/`now`.

- [internal/storage](internal/storage) — `S3Client` (AWS SDK v2) and `ClickHouseClient`. `S3Client` resolves each bucket's home region once (HeadBucket → `x-amz-bucket-region`, which S3 returns even on 301/403) and caches a per-region client, so the job's `AWS_REGION` need not match the bucket; when `AWS_ENDPOINT_URL` is set (RustFS/MinIO/LocalStack) it uses path-style addressing and skips region discovery. ClickHouse uses raw HTTP POST queries (only HTTP is supported — no native protocol); the URL is stored without a trailing slash. `SetupTable` auto-migrates older tables by adding a `source LowCardinality(String)` column when missing.
- [pkg/logger](pkg/logger) — colorized leveled logger gated by the `DEBUG` env var or `SetDebug(true)`.

### Table-name generation

`generateTableName` ([cmd/clickbom/main.go](cmd/clickbom/main.go)) is the contract between SBOM source and ClickHouse: `owner/repo` → `owner_repo`, Mend UUIDs become `mend_<uuid_underscored>`, Wiz/Trivy similar, and merge mode takes the S3 key minus its extension and appends `_merged` (`clickhouse.json` → `clickhouse_merged`). Changes here are user-visible (different table per run).

### Runtime image

The Dockerfile is multi-stage and ends on `gcr.io/distroless/cc-debian13:nonroot`. The runtime image contains the static `clickbom` binary, two external tools copied from the `tools` stage (`cyclonedx`, `trivy`; both version-pinned via `ARG` and SHA-256 verified at build time), `libz.so.1` copied from a `debian:13-slim` `libs` stage (the .NET host inside cyclonedx-cli fails at startup without it; `cc-debian12` did not ship zlib1g, `cc-debian13` does, so on Debian 13 the copy is redundant but harmless — keep that stage on the same Debian release as the distroless base; Dependabot bumps the `debian:N-slim` tag but cannot bump the distroless image, whose Debian release is part of the image name rather than the tag, so when a `debian` bump lands, move `cc-debianN` by hand in the same PR — #126 moved `libs` to 13 and left the runtime on 12), and `license-mappings.json`. Anything that needs to shell out must be one of those two tools (or added to the tools stage). The base image must stay a glibc variant (`cc`, or `base` + libstdc++): `cyclonedx-cli` is a dynamically linked .NET single-file app, and on `distroless/static` it fails with `fork/exec /usr/local/bin/cyclonedx: no such file or directory` (missing ELF interpreter) — that regression shipped once and broke every GitHub-sourced run. `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` is set so .NET starts without ICU. Tool versions and checksums are pinned via `ARG` (`CYCLONEDX_CLI_VERSION` + `CYCLONEDX_CLI_SHA256`, `TRIVY_VERSION`; Trivy is checked against its published `_checksums.txt`); Dependabot does not bump them, so update version and hash together. The `test_docker` CI job loads the built image and actually runs `cyclonedx convert` inside it — keep that smoke test if you touch the runtime stage.

## Conventions worth knowing

- `goimports` uses `-local github.com/ClickHouse/ClickBOM`, so internal imports go in their own block.
- Integration tests use `//go:build integration` and are excluded from the default `go test ./...` run. CI runs them in the `test_integration` job against RustFS (`rustfs/rustfs:1.0.0`, an Apache-2.0 store with a MinIO-compatible API: port 9000, `/minio/health/live`, root credentials via `RUSTFS_ACCESS_KEY`/`RUSTFS_SECRET_KEY`) and a `clickhouse/clickhouse-server` service container, with the `cyclonedx` CLI installed on the runner. Do not go back to MinIO: the project went source-only in October 2025, was archived in April 2026, and its Docker Hub and quay.io images were withdrawn in September 2026 (quay.io started answering `unauthorized` to anonymous pulls between 2026-09-21 and 2026-09-24, which is what broke the job). LocalStack's community image was discontinued and the remaining image needs an account and auth token. The RustFS tag is pinned by hand because Dependabot does not track images referenced in `run:` steps. Locally: start the same two containers (ClickHouse with `CLICKHOUSE_USER=clickbom CLICKHOUSE_PASSWORD=clickbom`; current images refuse the passwordless `default` user from outside the container), create `test-bucket`, put a `cyclonedx` binary on `PATH`, and export `AWS_ENDPOINT_URL`, `CLICKHOUSE_URL`, `CLICKHOUSE_USERNAME`/`CLICKHOUSE_PASSWORD`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `AWS_REGION` (see the command block above).
- Consumers: [ClickHouse/sbom](https://github.com/ClickHouse/sbom) (`private-government.yml`, `clickhouse-cloud.yml`) and, until fully migrated, [ClickHouse/security-integrations](https://github.com/ClickHouse/security-integrations) `clickbom.yml`. The sbom workflows pin the `v2.0.0` tag, so a fix reaches them only after a new tag and a ref bump; security-integrations pins `@main`. Never point a consumer at a feature branch: the ref breaks the moment the branch is deleted.
- Pre-commit blocks direct commits to `main`/`master` and enforces conventional commit messages.
- The Slack message may only carry inputs the README marks non-sensitive. The sensitive list lives in [internal/config](internal/config) (`sensitiveEnvVars`, `SecretsFromEnv`, `(*Config).Secrets`) and must be kept in sync with the README's Sensitive column; `secretsForRedaction` in [main.go](cmd/clickbom/main.go) adds the table-name spellings of Mend/Wiz identifiers (ClickHouse errors echo `db.mend_<uuid_underscored>`), and `buildSummary` names their scopes without identifiers and omits their ClickHouse table name. Never log `SLACK_WEBHOOK_URL`. Because error text now reaches Slack, any new `fmt.Errorf` that can embed a URL should go through `stripURL`/`redactURL` (see `internal/sbom/github.go`); the Wiz and Mend download errors do not yet, and rely on the notifier's URL scrubber.

- `gocyclo -over 26` is the hard cyclomatic-complexity ceiling; `handleNormalMode` and `handleMergeMode` are close to it — prefer extracting helpers when adding branches.
