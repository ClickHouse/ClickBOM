[![Test ClickBOM Action](https://github.com/ClickHouse/ClickBOM/actions/workflows/test.yml/badge.svg)](https://github.com/ClickHouse/ClickBOM/actions/workflows/test.yml)

# ClickBOM

Downloads SBOMs from GitHub. Uploads to S3 and ClickHouse.

# Inputs

| Name                  | Description                          | Default        | Required | Sensitive |
| --------------------- | ------------------------------------ | -------------- | -------- | --------- |
| github-token          | GitHub token for authentication      |                | true     | true      |
| ghapp-token           | GitHub App token for authentication  |                | false    | true      |
| aws-access-key-id     | AWS access key ID for S3 uploads     |                | true     | true      |
| aws-secret-access-key | AWS secret access key for S3 uploads |                | true     | true      |
| aws-region            | AWS region for S3 uploads            | us-east-1      | false    | false     |
| s3-bucket             | S3 bucket name for uploads           |                | false    | false     |
| s3-key                | S3 key prefix for uploads            | sbom/sbom.json | false    | false     |
| repository            | Repository to download SBOM from     |                | true     | false     |
| sbom-path             | Path to SBOM file in the repository  | sbom.json      | false    | false     |
| ref                   | Git reference (branch, tag, commit)  | main           | false    | false     |
| clickhouse-url        | ClickHouse URL for uploads           |                | false    | false     |
