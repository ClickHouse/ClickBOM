window.BENCHMARK_DATA = {
  "lastUpdate": 1761754011466,
  "repoUrl": "https://github.com/ClickHouse/ClickBOM",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "2b959fc806a0e7433ab61589d3bdf0697ab5f905",
          "message": "test: fix benchmark\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-10-25T16:52:41-05:00",
          "tree_id": "d183dd7ee213fa155313d318e918137dd528a15b",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/2b959fc806a0e7433ab61589d3bdf0697ab5f905"
        },
        "date": 1761429216903,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9297,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125852 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9297,
            "unit": "ns/op",
            "extra": "125852 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125852 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125852 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "0cd7d4d9885448070aa4951d965577499b91af43",
          "message": "test: fix security check\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-10-25T17:09:15-05:00",
          "tree_id": "f6bac4f4dcda9a893c34e8aacb62502ac3de0d9c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/0cd7d4d9885448070aa4951d965577499b91af43"
        },
        "date": 1761430219129,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9287,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "123212 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9287,
            "unit": "ns/op",
            "extra": "123212 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "123212 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "123212 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3568d114747f24bae3ddded8d321cd7f7da8787e",
          "message": "chore(feature/go): Init (#51)\n\n* chore(feature/go): Init\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* go\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* Dockerfile\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* .golangci\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* validation not defined\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* regexp and strings not used\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* io undefined\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: lint\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: docker build\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: e2e\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: fix benchmark\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: fix benchmark\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: fix security check\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n---------\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-10-25T17:15:07-05:00",
          "tree_id": "f6bac4f4dcda9a893c34e8aacb62502ac3de0d9c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/3568d114747f24bae3ddded8d321cd7f7da8787e"
        },
        "date": 1761430554587,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9308,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127689 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9308,
            "unit": "ns/op",
            "extra": "127689 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127689 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127689 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "4ac5c9d6b95495755203ee98256c7acfc6ff0099",
          "message": "chore(feature/go): License Mapper\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-10-27T14:03:30-04:00",
          "tree_id": "fab107a7f2c56eda8d4528f007048b20c58d9b21",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/4ac5c9d6b95495755203ee98256c7acfc6ff0099"
        },
        "date": 1761588268632,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9264,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124090 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9264,
            "unit": "ns/op",
            "extra": "124090 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124090 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124090 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5b3636db01c76d4eef6560db63bb212cdc24b7a9",
          "message": "chore(feature/go): License Mapper (#54)\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-10-27T15:33:19-04:00",
          "tree_id": "fab107a7f2c56eda8d4528f007048b20c58d9b21",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/5b3636db01c76d4eef6560db63bb212cdc24b7a9"
        },
        "date": 1761593646475,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9674,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "123913 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9674,
            "unit": "ns/op",
            "extra": "123913 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "123913 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "123913 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@clickhouse.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "953e3263fb940861964e6ecced7045e8a27d85ae",
          "message": "chore(feature/go): Trivy Integration\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-10-29T12:05:41-04:00",
          "tree_id": "edb9fe794c0921a1123c03d6a8eb4bf446bca935",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/953e3263fb940861964e6ecced7045e8a27d85ae"
        },
        "date": 1761754010915,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9416,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124401 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9416,
            "unit": "ns/op",
            "extra": "124401 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124401 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124401 times\n4 procs"
          }
        ]
      }
    ]
  }
}