[![Test ClickBOM Action](https://github.com/ClickHouse/ClickBOM/actions/workflows/test.yml/badge.svg)](https://github.com/ClickHouse/ClickBOM/actions/workflows/test.yml)

# ClickBOM

Downloads SBOMs from GitHub. Uploads to S3 and ClickHouse.

## Inputs

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

## Usage

### Same Repository

Simple example of downloading the SBOM from the same repository and uploading it to S3.

```yaml
name: Upload SBOM
on:
  push:
    branches:
      - main
      
jobs:
  clickbom:
    runs-on: ubuntu-latest

    permissions:
      id-token: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Configure AWS Credentials
        id: aws-creds
        uses: aws-actions/configure-aws-credentials@v1
        with:
          role-to-assume: arn:aws:iam::012345678912:role/GitHubOIDCRole
          role-session-name: clickbom-session
          aws-region: us-east-1

      - name: Upload SBOM
        uses: ./
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          aws-access-key-id: ${{ steps.aws-creds.outputs.aws-access-key-id }}
          aws-secret-access-key: ${{ steps.aws-creds.outputs.aws-secret-access-key }}
          s3-bucket: my-sbom-bucket
          s3-key: clickbom.json
```