window.BENCHMARK_DATA = {
  "lastUpdate": 1763178517739,
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
          "id": "5e441d0370dafc80b0c8361159ae8d33ff008212",
          "message": "fix(debug): extract from wrapper function\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-07T10:58:52-05:00",
          "tree_id": "241377affd970c870e393f9c67d6a352ea5f89e6",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/5e441d0370dafc80b0c8361159ae8d33ff008212"
        },
        "date": 1762531191714,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9240,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126114 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9240,
            "unit": "ns/op",
            "extra": "126114 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126114 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126114 times\n4 procs"
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
          "id": "3b433f5931a8705307fde2ea70f3b7763bfcba45",
          "message": "fix(debug): extract json from zip\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-07T11:34:32-05:00",
          "tree_id": "68db887d9c625e095c3fa9182e41d7f2664e329e",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/3b433f5931a8705307fde2ea70f3b7763bfcba45"
        },
        "date": 1762533337882,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9542,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124845 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9542,
            "unit": "ns/op",
            "extra": "124845 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124845 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124845 times\n4 procs"
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
          "id": "e36ba6e38d94c06e49defb456406f309b4d80397",
          "message": "fix(debug): remove debug print of sbom\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-07T11:41:47-05:00",
          "tree_id": "a2d3aad3b9be1876ba976cdc0713a047915b6997",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/e36ba6e38d94c06e49defb456406f309b4d80397"
        },
        "date": 1762533763908,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9269,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126127 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9269,
            "unit": "ns/op",
            "extra": "126127 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126127 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126127 times\n4 procs"
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
          "id": "96277d6adeddae027310dff8ba2a0d72e2dbc8a3",
          "message": "fix(aws): Some inputs are not longer required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-07T16:35:39-05:00",
          "tree_id": "a51b7d591cd3ced311e5cc6bb44760b46c22745d",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/96277d6adeddae027310dff8ba2a0d72e2dbc8a3"
        },
        "date": 1762551391903,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9375,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126417 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9375,
            "unit": "ns/op",
            "extra": "126417 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126417 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126417 times\n4 procs"
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
          "id": "4f25ce4756796cea87d05a8723ad3d5864b0e131",
          "message": "fix(aws): Some inputs are not longer required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-07T16:42:49-05:00",
          "tree_id": "e87a5e659b603aa3badefeffed3a97c13a4553c5",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/4f25ce4756796cea87d05a8723ad3d5864b0e131"
        },
        "date": 1762551828656,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9232,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126802 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9232,
            "unit": "ns/op",
            "extra": "126802 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126802 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126802 times\n4 procs"
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
          "id": "7fec6436589f110dc4de59822f779dae322eae90",
          "message": "fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-13T17:22:34-05:00",
          "tree_id": "4addda13f3f9087c92108671f68dc2940e26ef0f",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/7fec6436589f110dc4de59822f779dae322eae90"
        },
        "date": 1763072621659,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9291,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124942 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9291,
            "unit": "ns/op",
            "extra": "124942 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124942 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124942 times\n4 procs"
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
          "id": "faf30d7fc67888d9d1d4f178486159a946051399",
          "message": "fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-13T17:26:13-05:00",
          "tree_id": "492a8b671c4601561905330fe687976976b9236a",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/faf30d7fc67888d9d1d4f178486159a946051399"
        },
        "date": 1763072830247,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9292,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127683 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9292,
            "unit": "ns/op",
            "extra": "127683 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127683 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127683 times\n4 procs"
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
          "id": "d8526dd97341f34d03358b3102357af6e0442785",
          "message": "fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-13T17:33:05-05:00",
          "tree_id": "602c174c2ed1eea7a5833a1c51fe3b68375d1695",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/d8526dd97341f34d03358b3102357af6e0442785"
        },
        "date": 1763073251734,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9676,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124484 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9676,
            "unit": "ns/op",
            "extra": "124484 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124484 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124484 times\n4 procs"
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
          "id": "100d2b5222db206693fda3bde38b61332ea29bc8",
          "message": "fix: ecr auth\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T15:46:18-05:00",
          "tree_id": "f83e5c58a075a979ea3ae26007099c5274a5839a",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/100d2b5222db206693fda3bde38b61332ea29bc8"
        },
        "date": 1763153242375,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9343,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124340 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9343,
            "unit": "ns/op",
            "extra": "124340 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124340 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124340 times\n4 procs"
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
          "id": "667ce8111f7122fc7d816c6734328d18d6260cbe",
          "message": "fix: trivy clickhouse table name\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T18:05:05-05:00",
          "tree_id": "b0c58a1398a53d62bbc5f9fbb3cf7d19169f6a79",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/667ce8111f7122fc7d816c6734328d18d6260cbe"
        },
        "date": 1763161566883,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9304,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126288 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9304,
            "unit": "ns/op",
            "extra": "126288 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126288 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126288 times\n4 procs"
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
          "id": "e7ee3274beb46bc9c9b3f9ef454534bbf2c704b7",
          "message": "feat: ability to do application scope reports\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T20:54:34-05:00",
          "tree_id": "e7e1e667f01e2a9e678d00b691d5088c9ae0b1ef",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/e7ee3274beb46bc9c9b3f9ef454534bbf2c704b7"
        },
        "date": 1763171735491,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9338,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "123786 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9338,
            "unit": "ns/op",
            "extra": "123786 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "123786 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "123786 times\n4 procs"
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
          "id": "22a8ea1ba4ec09bd463d67b01c674f0c439be815",
          "message": "fix: i don't think org uuid is always required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T21:04:54-05:00",
          "tree_id": "20c03f4436f0a67167b48ff937b166441a1f4450",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/22a8ea1ba4ec09bd463d67b01c674f0c439be815"
        },
        "date": 1763172360371,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9304,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126046 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9304,
            "unit": "ns/op",
            "extra": "126046 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126046 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126046 times\n4 procs"
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
          "id": "745a1df6072ab062bcf7d12c1b729026d0afde40",
          "message": "fix: if no projectUuids are provided\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T21:11:27-05:00",
          "tree_id": "84df60830f7aea00c156a69830a75ecd8987b006",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/745a1df6072ab062bcf7d12c1b729026d0afde40"
        },
        "date": 1763172745539,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 5279,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "213306 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 5279,
            "unit": "ns/op",
            "extra": "213306 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "213306 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "213306 times\n4 procs"
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
          "id": "f4836d19d963931a8f21c1c765f6050f62cab439",
          "message": "fix: mend-project-uuids\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T21:34:21-05:00",
          "tree_id": "894690dad588794ace0cb3ea8eb763ae6a02854c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/f4836d19d963931a8f21c1c765f6050f62cab439"
        },
        "date": 1763174119501,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9413,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124786 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9413,
            "unit": "ns/op",
            "extra": "124786 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124786 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124786 times\n4 procs"
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
          "id": "400b32d757bc17e91feadcd31dd6574b6dad18d4",
          "message": "fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T21:47:11-05:00",
          "tree_id": "77781ac2428efcf019f40a33d2273cf3e968a60e",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/400b32d757bc17e91feadcd31dd6574b6dad18d4"
        },
        "date": 1763174889988,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9292,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125618 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9292,
            "unit": "ns/op",
            "extra": "125618 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125618 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125618 times\n4 procs"
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
          "id": "fe1fe95b8a231064a6fbf3eef2c14e332220dc78",
          "message": "fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T21:51:30-05:00",
          "tree_id": "0e7dbdac58a51e4747a81c37e8d036e726cbd4e0",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/fe1fe95b8a231064a6fbf3eef2c14e332220dc78"
        },
        "date": 1763175149193,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9341,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125292 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9341,
            "unit": "ns/op",
            "extra": "125292 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125292 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125292 times\n4 procs"
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
          "id": "dd7ea7d19f25085a650b1ac7a09d37b42c55b268",
          "message": "fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T21:54:10-05:00",
          "tree_id": "732a6f86f3341ba1033e400705489c2e7026a091",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/dd7ea7d19f25085a650b1ac7a09d37b42c55b268"
        },
        "date": 1763175307490,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9359,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124011 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9359,
            "unit": "ns/op",
            "extra": "124011 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124011 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124011 times\n4 procs"
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
          "id": "7d693a494915be21439deb9fa20fb5a01b6035fb",
          "message": "fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T21:56:10-05:00",
          "tree_id": "644b3ccb4cd3e43705e829885f98a3ed7d1de03c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/7d693a494915be21439deb9fa20fb5a01b6035fb"
        },
        "date": 1763175427155,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9351,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124695 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9351,
            "unit": "ns/op",
            "extra": "124695 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124695 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124695 times\n4 procs"
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
          "id": "9f47927607c8eafa32c81501b600cf8376699a5c",
          "message": "fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T22:02:19-05:00",
          "tree_id": "19ad7af9c245e238f22396183e9c86f06d87b216",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/9f47927607c8eafa32c81501b600cf8376699a5c"
        },
        "date": 1763175795122,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9302,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124568 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9302,
            "unit": "ns/op",
            "extra": "124568 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124568 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124568 times\n4 procs"
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
          "id": "5cbe317c60aec555091a2f73007ed63e9e673bf1",
          "message": "fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T22:05:21-05:00",
          "tree_id": "2998ba4b57b0dfc88fdf24815b02288960813375",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/5cbe317c60aec555091a2f73007ed63e9e673bf1"
        },
        "date": 1763175980034,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9395,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "122769 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9395,
            "unit": "ns/op",
            "extra": "122769 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "122769 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "122769 times\n4 procs"
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
          "id": "c9adcf81ec0161e62bcc585c78f617a8333b0eda",
          "message": "fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T22:10:41-05:00",
          "tree_id": "19ad7af9c245e238f22396183e9c86f06d87b216",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/c9adcf81ec0161e62bcc585c78f617a8333b0eda"
        },
        "date": 1763176300701,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9426,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124513 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9426,
            "unit": "ns/op",
            "extra": "124513 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124513 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124513 times\n4 procs"
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
          "id": "80055ec51305f7e84ea03e514e86f3010f104dbe",
          "message": "fix: stuff\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T22:47:33-05:00",
          "tree_id": "4a05b43be9d967da3b4dafd1ecbaf6f3593174fb",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/80055ec51305f7e84ea03e514e86f3010f104dbe"
        },
        "date": 1763178517287,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9427,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125126 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9427,
            "unit": "ns/op",
            "extra": "125126 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125126 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125126 times\n4 procs"
          }
        ]
      }
    ]
  }
}