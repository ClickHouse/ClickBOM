# ClickBOM

Downloads SBOMs from GitHub. Uploads to S3 and ClickHouse.

# Inputs

| Name           | Description                           | Required | Sensitive |
| -------------- | ------------------------------------- | -------- | --------- |
| GITHUB_TOKEN   | GitHub token for authentication       | true     | true      |
| GHAPP_TOKEN    | GitHub App token for authentication   | false    | true      |
| S3_BUCKET      | S3 bucket name for uploads            | true     | false     |
| CLICKHOUSE_URL | ClickHouse URL for uploads            | true     | false     |
