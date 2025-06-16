# ClickBOM

Downloads SBOMs from GitHub. Uploads to S3 and ClickHouse.

# Inputs

| Name | Description | Required | Secret |
| ---- | ----------- | -------- | ------ |
| GITHUB_TOKEN | GitHub token for authentication | true | true |
| MEND_API_KEY | Mend API key for authentication | true | true |
| WIZ_API_KEY | Wiz API key for authentication | true | true |
| S3_BUCKET | S3 bucket name for uploads | true | false |
| CLICKHOUSE_URL | ClickHouse URL for uploads | true | false |
