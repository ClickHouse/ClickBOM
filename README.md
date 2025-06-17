[![Test ClickBOM Action](https://github.com/ClickHouse/ClickBOM/actions/workflows/test.yml/badge.svg)](https://github.com/ClickHouse/ClickBOM/actions/workflows/test.yml)

# ClickBOM

Downloads SBOMs from GitHub. Uploads to S3 and ClickHouse.

- [Inputs](#inputs)
  - [Notes](#notes)
- [Usage](#usage)
  - [Same Repository](#same-repository)
  - [Same Repository with ClickHouse](#same-repository-with-clickhouse)
  - [Same Repository with GitHub App](#same-repository-with-github-app)
- [Creating a GitHub App](#creating-a-github-app)

## Inputs

| Name                  | Description                         | Default        | Required | Sensitive |
| --------------------- | ----------------------------------- | -------------- | -------- | --------- |
| github-token          | GitHub Token                        |                | false    | true      |
| aws-access-key-id     | AWS Access Key ID                   |                | true     | true      |
| aws-secret-access-key | AWS Secret Access Key               |                | true     | true      |
| aws-region            | AWS Region                          | us-east-1      | false    | false     |
| s3-bucket             | S3 Bucket Name                      |                | false    | false     |
| s3-key                | S3 Key Prefix                       | sbom/sbom.json | false    | false     |
| repository            | Repository to download SBOM from    |                | true     | false     |
| sbom-format           | SBOM format (spdxjson or cyclonedx) | cyclonedx      | false    | false     |
| clickhouse-url        | ClickHouse URL                      |                | false    | true      |
| clickhouse-database   | ClickHouse Database Name            | default        | false    | false     |
| clickhouse-username   | ClickHouse Username                 | default        | false    | false     |
| clickhouse-password   | ClickHouse Password                 | (empty)        | false    | true      |

### Notes

- Either `github-token` or `ghapp-token` must be provided for authentication to the GitHub API.
- `sbom-format` specifies the format you want the final SBOM to be in. For example, GitHub only supports SPDX, settings this input to `cyclonedx` will convert the SBOM to CycloneDX format.
- At the moment, ClickHouse ingestion is only supported over HTTP.

## Usage

### Same Repository

Simple example of downloading the SBOM from the same repository and uploading it to S3. Converts the SBOM to CycloneDX format.

```yaml
name: Upload SBOM
on:
  push:
    branches:
      - main
      
jobs:
  clickbom:
    name: ClickBOM
    runs-on: ubuntu-latest

    permissions:
      id-token: write
      contents: read

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
          repository: ${{ github.repository }}
```

### Same Repository with ClickHouse

Downloads the SBOM from the same repository and uploads it to S3. Converts the SBOM to CycloneDX format. Also uploads the SBOM to ClickHouse.

```yaml
name: Upload SBOM
on:
  push:
    branches:
      - main
      
jobs:
  clickbom:
    name: ClickBOM
    runs-on: ubuntu-latest

    permissions:
      id-token: write
      contents: read

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
          repository: ${{ github.repository }}
          clickhouse-url: ${{ secrets.CLICKHOUSE_URL }}
          clickhouse-database: ${{ secrets.CLICKHOUSE_DATABASE }}
          clickhouse-username: ${{ secrets.CLICKHOUSE_USERNAME }}
          clickhouse-password: ${{ secrets.CLICKHOUSE_PASSWORD }}
```

### Same Repository with GitHub App

Downloads the SBOM from the same repository and uploads it to S3. Keeps the SBOM in SPDX format. Authenticates using a GitHub App.

```yaml
name: Upload SBOM
on:
  push:
    branches:
      - main
      
jobs:
  clickbom:
    name: ClickBOM
    runs-on: ubuntu-latest

    permissions:
      id-token: write
      contents: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v2

      - name: Generate Token
        id: generate-token
        uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ secrets.CLICKBOM_AUTH_APP_ID }}
          private-key: ${{ secrets.CLICKBOM_AUTH_PRIVATE_KEY }}

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
          github-token: ${{ steps.generate-token.outputs.token }}
          aws-access-key-id: ${{ steps.aws-creds.outputs.aws-access-key-id }}
          aws-secret-access-key: ${{ steps.aws-creds.outputs.aws-secret-access-key }}
          sbom-format: spdxjson
          s3-bucket: my-sbom-bucket
          s3-key: clickbom.json
          repository: ${{ github.repository }}
          clickhouse-url: ${{ secrets.CLICKHOUSE_URL }}
          clickhouse-database: ${{ secrets.CLICKHOUSE_DATABASE }}
          clickhouse-username: ${{ secrets.CLICKHOUSE_USERNAME }}
          clickhouse-password: ${{ secrets.CLICKHOUSE_PASSWORD }}
```

## Creating a GitHub App

- Follow the instructions [here](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app) to create a GitHub App.
- Make sure to give the app `Read access` to `Contents` and `Metadata`.
- Install the app on the repositories you want to use it with.
- Generate a private key for the app and save it somewhere secure, i.e. GitHub Secrets.