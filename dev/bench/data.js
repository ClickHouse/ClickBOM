window.BENCHMARK_DATA = {
  "lastUpdate": 1781521878132,
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
          "id": "88b80be48024568dc50034029e65d5bbd7e7e9c5",
          "message": "feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T23:09:31-05:00",
          "tree_id": "1a024682d642a37a3bf0384873314041318f2bbf",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/88b80be48024568dc50034029e65d5bbd7e7e9c5"
        },
        "date": 1763179827702,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9407,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "123650 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9407,
            "unit": "ns/op",
            "extra": "123650 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "123650 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "123650 times\n4 procs"
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
          "id": "e7a5e5e0f0fd036d4012719cbd43bd9622b395a9",
          "message": "feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T23:24:55-05:00",
          "tree_id": "e99a5bf064c2ebb543ee860e0941527c5b6b6ca8",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/e7a5e5e0f0fd036d4012719cbd43bd9622b395a9"
        },
        "date": 1763180755054,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9209,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125359 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9209,
            "unit": "ns/op",
            "extra": "125359 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125359 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125359 times\n4 procs"
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
          "id": "4547913aa66c7f27ddf4c2adb322fdcee02054bf",
          "message": "feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T23:27:25-05:00",
          "tree_id": "f8fbcbb574f50bd7eab781e72c384fc498eb629c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/4547913aa66c7f27ddf4c2adb322fdcee02054bf"
        },
        "date": 1763180902518,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9424,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124198 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9424,
            "unit": "ns/op",
            "extra": "124198 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124198 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124198 times\n4 procs"
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
          "id": "7b39d425ff9868c6c760d6748c6cdb472696dacf",
          "message": "fix: lint\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T23:45:43-05:00",
          "tree_id": "34213c278ec752eedaf0980f45cfe74080d6ca5c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/7b39d425ff9868c6c760d6748c6cdb472696dacf"
        },
        "date": 1763182004455,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9217,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127818 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9217,
            "unit": "ns/op",
            "extra": "127818 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127818 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127818 times\n4 procs"
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
          "id": "d9247c392fc47c00bb929fa8c2e824fc440f7e1a",
          "message": "chore(feature/go): Trivy Integration (#55)\n\n* chore(feature/go): Trivy Integration\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(debug): extract from wrapper function\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(debug): extract json from zip\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(debug): remove debug print of sbom\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(aws): Some inputs are not longer required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(aws): Some inputs are not longer required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: ecr auth\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: trivy clickhouse table name\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: ability to do application scope reports\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: i don't think org uuid is always required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: if no projectUuids are provided\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: mend-project-uuids\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: stuff\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: lint\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n---------\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-11-14T23:51:21-05:00",
          "tree_id": "34213c278ec752eedaf0980f45cfe74080d6ca5c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/d9247c392fc47c00bb929fa8c2e824fc440f7e1a"
        },
        "date": 1763182326950,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9284,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127168 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9284,
            "unit": "ns/op",
            "extra": "127168 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127168 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127168 times\n4 procs"
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
          "id": "9c5d8e8025179eae0a814e1caf2b4340d09ddb29",
          "message": "feat(go): License Updates and Test Migrations\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-12-14T21:47:48-05:00",
          "tree_id": "8959a42cc8f70f1838d55a1c03d9632aca8ad1c3",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/9c5d8e8025179eae0a814e1caf2b4340d09ddb29"
        },
        "date": 1765766924144,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9205,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126799 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9205,
            "unit": "ns/op",
            "extra": "126799 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126799 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126799 times\n4 procs"
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
          "id": "1aadf4f580e777b36d961864a3b3140457acb3ca",
          "message": "feat(go): License Updates and Test Migrations\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2025-12-14T21:53:39-05:00",
          "tree_id": "88e77495d0211cc6a5531489838d89c4ac1244a2",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/1aadf4f580e777b36d961864a3b3140457acb3ca"
        },
        "date": 1765767276824,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9308,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125546 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9308,
            "unit": "ns/op",
            "extra": "125546 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125546 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125546 times\n4 procs"
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
          "id": "feede275309ea32ddb771f98c1f5316a1c25485d",
          "message": "chore: more licenses\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2026-01-11T17:09:21-05:00",
          "tree_id": "f171d393de0b35d994f993c6b1b8efde486640d1",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/feede275309ea32ddb771f98c1f5316a1c25485d"
        },
        "date": 1768169412409,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 5387,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "216871 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 5387,
            "unit": "ns/op",
            "extra": "216871 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "216871 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "216871 times\n4 procs"
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
          "id": "4ee8fc7f013befdb84e69427d27ae52966f05b09",
          "message": "fix: merged problem\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>",
          "timestamp": "2026-01-12T20:08:20-05:00",
          "tree_id": "ee7d0c8b7f555b1edadf3730eb14963887e52ca4",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/4ee8fc7f013befdb84e69427d27ae52966f05b09"
        },
        "date": 1768266560093,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9219,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127209 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9219,
            "unit": "ns/op",
            "extra": "127209 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127209 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127209 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "7cfbdf8da87ee4b34d459827bf259e75f824de66",
          "message": "Merge branch 'main' into feature/go-complete-migration",
          "timestamp": "2026-05-13T10:50:39-04:00",
          "tree_id": "6535cb906a7915582d9670200145470bf1c01cc2",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/7cfbdf8da87ee4b34d459827bf259e75f824de66"
        },
        "date": 1778683939269,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 8898,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "132042 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 8898,
            "unit": "ns/op",
            "extra": "132042 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "132042 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "132042 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "9866a6b828b92afc786d0454a95354f8674244f9",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:00:21-04:00",
          "tree_id": "5c3b8fd3a7f562019b4bc3db402ff1e1185ce67a",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/9866a6b828b92afc786d0454a95354f8674244f9"
        },
        "date": 1778684479989,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11738,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "106006 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11738,
            "unit": "ns/op",
            "extra": "106006 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "106006 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "106006 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "7ba6f554015f1435416393c07d8f1051850fb16a",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:03:49-04:00",
          "tree_id": "e088fea96d0e6e5a0630cbac430df28c4a43d544",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/7ba6f554015f1435416393c07d8f1051850fb16a"
        },
        "date": 1778684685926,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9772,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126007 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9772,
            "unit": "ns/op",
            "extra": "126007 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126007 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126007 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "cdf36137a52c2a0fe23544f11f75b213a6ea8da1",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:08:05-04:00",
          "tree_id": "990cbc433518c6d40a19df3d12b1e2516757203f",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/cdf36137a52c2a0fe23544f11f75b213a6ea8da1"
        },
        "date": 1778684942571,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11642,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "103483 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11642,
            "unit": "ns/op",
            "extra": "103483 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "103483 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "103483 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "60b4f11d3ebc7921b66332830b822c7f1e935fd7",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:14:25-04:00",
          "tree_id": "c9c15495356b11ae9c73fdf2c19e4a161563a47c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/60b4f11d3ebc7921b66332830b822c7f1e935fd7"
        },
        "date": 1778685316635,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9276,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126291 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9276,
            "unit": "ns/op",
            "extra": "126291 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126291 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126291 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "e48f51c5eb45880da21e4f8cfb6419598716e178",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:20:14-04:00",
          "tree_id": "432011e33a6d6b550af0dc94629e82aa618025c0",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/e48f51c5eb45880da21e4f8cfb6419598716e178"
        },
        "date": 1778685678807,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9273,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "129880 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9273,
            "unit": "ns/op",
            "extra": "129880 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "129880 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "129880 times\n4 procs"
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
          "id": "077c4357c8d98b90c03c9cd8ab65a5870a48a6c1",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration (#63)\n\n* Bump actions/download-artifact from 5 to 6 in /.github/workflows (#53)\n\nBumps [actions/download-artifact](https://github.com/actions/download-artifact) from 5 to 6.\n- [Release notes](https://github.com/actions/download-artifact/releases)\n- [Commits](https://github.com/actions/download-artifact/compare/v5...v6)\n\n---\nupdated-dependencies:\n- dependency-name: actions/download-artifact\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\n\n* Bump actions/upload-artifact from 4 to 5 in /.github/workflows (#52)\n\nBumps [actions/upload-artifact](https://github.com/actions/upload-artifact) from 4 to 5.\n- [Release notes](https://github.com/actions/upload-artifact/releases)\n- [Commits](https://github.com/actions/upload-artifact/compare/v4...v5)\n\n---\nupdated-dependencies:\n- dependency-name: actions/upload-artifact\n  dependency-version: '5'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\n\n* Bump actions/checkout from 5 to 6 in /.github/workflows (#56)\n\nBumps [actions/checkout](https://github.com/actions/checkout) from 5 to 6.\n- [Release notes](https://github.com/actions/checkout/releases)\n- [Changelog](https://github.com/actions/checkout/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/actions/checkout/compare/v5...v6)\n\n---\nupdated-dependencies:\n- dependency-name: actions/checkout\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n---------\n\nSigned-off-by: dependabot[bot] <support@github.com>\nSigned-off-by: Julio Jimenez <julio@julioj.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T11:24:59-04:00",
          "tree_id": "432011e33a6d6b550af0dc94629e82aa618025c0",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/077c4357c8d98b90c03c9cd8ab65a5870a48a6c1"
        },
        "date": 1778685953454,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9310,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127882 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9310,
            "unit": "ns/op",
            "extra": "127882 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127882 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127882 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "e8a0e952f4e10026a5e92ca511be72389edce52d",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:39:20-04:00",
          "tree_id": "a18709dfd92abb2a0cf010cc6ea7b744144a39bd",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/e8a0e952f4e10026a5e92ca511be72389edce52d"
        },
        "date": 1778686821159,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11677,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "101498 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11677,
            "unit": "ns/op",
            "extra": "101498 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "101498 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "101498 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "4dbd51b526a4da3a8dfbbe9531910dc7af969d94",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:44:02-04:00",
          "tree_id": "6669aa58b782c1501ebd79f554397c238177996f",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/4dbd51b526a4da3a8dfbbe9531910dc7af969d94"
        },
        "date": 1778687092788,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 5800,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "208501 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 5800,
            "unit": "ns/op",
            "extra": "208501 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "208501 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "208501 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "18bd4421f86fb70dffd6120c787d71e73926f2d3",
          "message": "feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T11:45:00-04:00",
          "tree_id": "877f6a4177ec34edb3aa133ffafa90516906c14e",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/18bd4421f86fb70dffd6120c787d71e73926f2d3"
        },
        "date": 1778687156617,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9344,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "128643 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9344,
            "unit": "ns/op",
            "extra": "128643 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "128643 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "128643 times\n4 procs"
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
          "id": "75fa68ef7ab94c322143a3a9626c6b53bbee6b4c",
          "message": "Potential fix for pull request finding\n\nCo-authored-by: Copilot Autofix powered by AI <175728472+Copilot@users.noreply.github.com>",
          "timestamp": "2026-05-13T11:49:14-04:00",
          "tree_id": "215d69ed6272f75dcf7a7b6c1884f9290db5a513",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/75fa68ef7ab94c322143a3a9626c6b53bbee6b4c"
        },
        "date": 1778687382773,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9505,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127466 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9505,
            "unit": "ns/op",
            "extra": "127466 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127466 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127466 times\n4 procs"
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
          "id": "2d8da79bf1b02ad739b62b9cc40dd6507f57f7ec",
          "message": "Potential fix for pull request finding\n\nCo-authored-by: Copilot Autofix powered by AI <175728472+Copilot@users.noreply.github.com>",
          "timestamp": "2026-05-13T11:50:03-04:00",
          "tree_id": "d0d9ec9a191c7a867c5e4f9132711902c4e5775f",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/2d8da79bf1b02ad739b62b9cc40dd6507f57f7ec"
        },
        "date": 1778687433298,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9202,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "130701 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9202,
            "unit": "ns/op",
            "extra": "130701 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "130701 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "130701 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "9e58c605a6f906527a13bfa27ae350441f2c04dd",
          "message": "feat(go): Migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T12:09:38-04:00",
          "tree_id": "38a2198d6992ea67f5b71321a125cc8dfa8fd4ae",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/9e58c605a6f906527a13bfa27ae350441f2c04dd"
        },
        "date": 1778688621756,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9504,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126282 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9504,
            "unit": "ns/op",
            "extra": "126282 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126282 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126282 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "9d2dfeb15daa3e8050cb4d0d4d4617d5916327c7",
          "message": "feat(go): Migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T12:12:16-04:00",
          "tree_id": "22f77ef76ad4dceade8cb407e34395651ef94afb",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/9d2dfeb15daa3e8050cb4d0d4d4617d5916327c7"
        },
        "date": 1778688789685,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9390,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127534 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9390,
            "unit": "ns/op",
            "extra": "127534 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127534 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127534 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "6c101f54152ed5d5aa62cfb682adfe716a617ac3",
          "message": "feat(go): Migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T12:21:52-04:00",
          "tree_id": "7d6075bd5ee4ef4995967ef9a4f37cd493f23821",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/6c101f54152ed5d5aa62cfb682adfe716a617ac3"
        },
        "date": 1778689372165,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9338,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "128418 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9338,
            "unit": "ns/op",
            "extra": "128418 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "128418 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "128418 times\n4 procs"
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
          "id": "b18f7bafb1b9a22d539f162009adb272d03e6fab",
          "message": "feat(go): Migration (#64)\n\n* chore(feature/go): Init (#51)\n\n* chore(feature/go): Init\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* go\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* Dockerfile\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* .golangci\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* validation not defined\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* regexp and strings not used\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* io undefined\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: pre-commit\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: integration test\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: lint\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: docker build\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: e2e\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: fix benchmark\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: fix benchmark\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* test: fix security check\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n---------\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* chore(feature/go): License Mapper (#54)\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* chore(feature/go): Trivy Integration (#55)\n\n* chore(feature/go): Trivy Integration\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(debug): extract from wrapper function\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(debug): extract json from zip\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(debug): remove debug print of sbom\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(aws): Some inputs are not longer required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix(aws): Some inputs are not longer required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: add trivy to config validation\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: ecr auth\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: trivy clickhouse table name\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: ability to do application scope reports\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: i don't think org uuid is always required\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: if no projectUuids are provided\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: mend-project-uuids\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: maxDepthLevel\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: stuff\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat: add merge\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* fix: lint\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n---------\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration (#63)\n\n* Bump actions/download-artifact from 5 to 6 in /.github/workflows (#53)\n\nBumps [actions/download-artifact](https://github.com/actions/download-artifact) from 5 to 6.\n- [Release notes](https://github.com/actions/download-artifact/releases)\n- [Commits](https://github.com/actions/download-artifact/compare/v5...v6)\n\n---\nupdated-dependencies:\n- dependency-name: actions/download-artifact\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\n\n* Bump actions/upload-artifact from 4 to 5 in /.github/workflows (#52)\n\nBumps [actions/upload-artifact](https://github.com/actions/upload-artifact) from 4 to 5.\n- [Release notes](https://github.com/actions/upload-artifact/releases)\n- [Commits](https://github.com/actions/upload-artifact/compare/v4...v5)\n\n---\nupdated-dependencies:\n- dependency-name: actions/upload-artifact\n  dependency-version: '5'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\n\n* Bump actions/checkout from 5 to 6 in /.github/workflows (#56)\n\nBumps [actions/checkout](https://github.com/actions/checkout) from 5 to 6.\n- [Release notes](https://github.com/actions/checkout/releases)\n- [Changelog](https://github.com/actions/checkout/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/actions/checkout/compare/v5...v6)\n\n---\nupdated-dependencies:\n- dependency-name: actions/checkout\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(parity): close bashgo gaps before merging feature/go-complete-migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n---------\n\nSigned-off-by: dependabot[bot] <support@github.com>\nSigned-off-by: Julio Jimenez <julio@julioj.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\n\n* Potential fix for pull request finding\n\nCo-authored-by: Copilot Autofix powered by AI <175728472+Copilot@users.noreply.github.com>\n\n* Potential fix for pull request finding\n\nCo-authored-by: Copilot Autofix powered by AI <175728472+Copilot@users.noreply.github.com>\n\n* feat(go): Migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(go): Migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n* feat(go): Migration\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>\n\n---------\n\nSigned-off-by: Julio Jimenez <julio@clickhouse.com>\nSigned-off-by: dependabot[bot] <support@github.com>\nSigned-off-by: Julio Jimenez <julio@julioj.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\nCo-authored-by: Copilot Autofix powered by AI <175728472+Copilot@users.noreply.github.com>",
          "timestamp": "2026-05-13T12:28:53-04:00",
          "tree_id": "523730bdd6e412093d7410bd824ff66053e8c12a",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/b18f7bafb1b9a22d539f162009adb272d03e6fab"
        },
        "date": 1778689773363,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11338,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "104188 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11338,
            "unit": "ns/op",
            "extra": "104188 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "104188 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "104188 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a3cfd1db83e4ec18c92000c277ee1fe0f2fa934b",
          "message": "Bump actions/checkout from 5 to 6 in /.github/workflows\n\nBumps [actions/checkout](https://github.com/actions/checkout) from 5 to 6.\n- [Release notes](https://github.com/actions/checkout/releases)\n- [Changelog](https://github.com/actions/checkout/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/actions/checkout/compare/v5...v6)\n\n---\nupdated-dependencies:\n- dependency-name: actions/checkout\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:29:54Z",
          "tree_id": "ce7f1951f14319ffc91e678d93ace05197f869f0",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/a3cfd1db83e4ec18c92000c277ee1fe0f2fa934b"
        },
        "date": 1778689846448,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9353,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "129247 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9353,
            "unit": "ns/op",
            "extra": "129247 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "129247 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "129247 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "23c9fa30b7f6c469c5231c2db9d5705e3e146eec",
          "message": "Bump codecov/codecov-action from 4 to 6 in /.github/workflows\n\nBumps [codecov/codecov-action](https://github.com/codecov/codecov-action) from 4 to 6.\n- [Release notes](https://github.com/codecov/codecov-action/releases)\n- [Changelog](https://github.com/codecov/codecov-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/codecov/codecov-action/compare/v4...v6)\n\n---\nupdated-dependencies:\n- dependency-name: codecov/codecov-action\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:30:00Z",
          "tree_id": "175bc2df483c974d29a169b8bd2ec50916af18c9",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/23c9fa30b7f6c469c5231c2db9d5705e3e146eec"
        },
        "date": 1778689848908,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 8784,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "132016 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 8784,
            "unit": "ns/op",
            "extra": "132016 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "132016 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "132016 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1828f400defa3f89d35f96c2d3fdef2041795a6b",
          "message": "Bump golang from 1.25.10-alpine3.22 to 1.26.3-alpine3.22\n\nBumps golang from 1.25.10-alpine3.22 to 1.26.3-alpine3.22.\n\n---\nupdated-dependencies:\n- dependency-name: golang\n  dependency-version: 1.26.3-alpine3.22\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:30:09Z",
          "tree_id": "a144f7563c87211f022d25644ac07add430d4704",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/1828f400defa3f89d35f96c2d3fdef2041795a6b"
        },
        "date": 1778689852141,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 8952,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "135463 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 8952,
            "unit": "ns/op",
            "extra": "135463 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "135463 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "135463 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "24b9b031c64ce0facd8e09f7731a1f6e5f1371f9",
          "message": "Bump alpine from 3.19 to 3.23\n\nBumps alpine from 3.19 to 3.23.\n\n---\nupdated-dependencies:\n- dependency-name: alpine\n  dependency-version: '3.23'\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:30:03Z",
          "tree_id": "f7df85cda28ec4cc50358b331f40bcacbf9560e6",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/24b9b031c64ce0facd8e09f7731a1f6e5f1371f9"
        },
        "date": 1778689853111,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9513,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "123412 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9513,
            "unit": "ns/op",
            "extra": "123412 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "123412 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "123412 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "73905bd8804ad1de85975dc383f04b47df88fe7b",
          "message": "Bump golangci/golangci-lint-action from 8 to 9 in /.github/workflows\n\nBumps [golangci/golangci-lint-action](https://github.com/golangci/golangci-lint-action) from 8 to 9.\n- [Release notes](https://github.com/golangci/golangci-lint-action/releases)\n- [Commits](https://github.com/golangci/golangci-lint-action/compare/v8...v9)\n\n---\nupdated-dependencies:\n- dependency-name: golangci/golangci-lint-action\n  dependency-version: '9'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:29:57Z",
          "tree_id": "b7b196e8c424bd3bafd30809d65cdf8c5169e6e3",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/73905bd8804ad1de85975dc383f04b47df88fe7b"
        },
        "date": 1778689855694,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9706,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "124063 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9706,
            "unit": "ns/op",
            "extra": "124063 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "124063 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "124063 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2b268ccf4d2fc61aa7279694262868e3795f8594",
          "message": "Bump actions/download-artifact from 6 to 8 in /.github/workflows (#62)\n\nBumps [actions/download-artifact](https://github.com/actions/download-artifact) from 6 to 8.\n- [Release notes](https://github.com/actions/download-artifact/releases)\n- [Commits](https://github.com/actions/download-artifact/compare/v6...v8)\n\n---\nupdated-dependencies:\n- dependency-name: actions/download-artifact\n  dependency-version: '8'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T12:30:27-04:00",
          "tree_id": "c60b8ac8170c7f2149ae894aba3cb0d883a75bfa",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/2b268ccf4d2fc61aa7279694262868e3795f8594"
        },
        "date": 1778689887504,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9451,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126492 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9451,
            "unit": "ns/op",
            "extra": "126492 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126492 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126492 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "268ad038050166cfd60a7950df6c43d18b3d7185",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.31.15 to 1.32.17\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.31.15 to 1.32.17.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.31.15...config/v1.32.17)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.17\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:31:24Z",
          "tree_id": "044a85277f296697963b263437cf87a35117de50",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/268ad038050166cfd60a7950df6c43d18b3d7185"
        },
        "date": 1778689929752,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 5704,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "209793 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 5704,
            "unit": "ns/op",
            "extra": "209793 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "209793 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "209793 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ec131f942e56755218571aaf96b1355702e84bb5",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.97.3 to 1.101.0\n\nBumps [github.com/aws/aws-sdk-go-v2/service/s3](https://github.com/aws/aws-sdk-go-v2) from 1.97.3 to 1.101.0.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/s3/v1.97.3...service/s3/v1.101.0)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/s3\n  dependency-version: 1.101.0\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:32:38Z",
          "tree_id": "94393cfb47e3b7421b1290a6fc4700581de12ef6",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/ec131f942e56755218571aaf96b1355702e84bb5"
        },
        "date": 1778689999508,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11506,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "103452 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11506,
            "unit": "ns/op",
            "extra": "103452 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "103452 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "103452 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "df76122c1598dd8d34176101923afa086ab0992d",
          "message": "Bump github.com/aws/aws-sdk-go-v2 from 1.41.5 to 1.41.7\n\nBumps [github.com/aws/aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) from 1.41.5 to 1.41.7.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/v1.41.5...v1.41.7)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2\n  dependency-version: 1.41.7\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:33:50Z",
          "tree_id": "58ab444c9b02e86f124c3809f04e135524fed132",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/df76122c1598dd8d34176101923afa086ab0992d"
        },
        "date": 1778690074461,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9547,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125575 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9547,
            "unit": "ns/op",
            "extra": "125575 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125575 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125575 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "20bcbce3ef0eac4614249b66fe295d41d7c064b9",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/sts from 1.38.9 to 1.42.1\n\nBumps [github.com/aws/aws-sdk-go-v2/service/sts](https://github.com/aws/aws-sdk-go-v2) from 1.38.9 to 1.42.1.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/sts/v1.38.9...service/s3/v1.42.1)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/sts\n  dependency-version: 1.42.1\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T16:35:03Z",
          "tree_id": "611943531c05507bdba402023722879afc25e8e4",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/20bcbce3ef0eac4614249b66fe295d41d7c064b9"
        },
        "date": 1778690145310,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11636,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "105240 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11636,
            "unit": "ns/op",
            "extra": "105240 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "105240 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "105240 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "99b6544837b9a8e711a3f54f6250fb6a4c51a6fe",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/sts from 1.38.9 to 1.42.1 (#73)\n\nBumps [github.com/aws/aws-sdk-go-v2/service/sts](https://github.com/aws/aws-sdk-go-v2) from 1.38.9 to 1.42.1.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/sts/v1.38.9...service/s3/v1.42.1)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/sts\n  dependency-version: 1.42.1\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:30:49-04:00",
          "tree_id": "c6724bf8339762cecccdef5faa1f844333f45e5f",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/99b6544837b9a8e711a3f54f6250fb6a4c51a6fe"
        },
        "date": 1778700688374,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11747,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "104710 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11747,
            "unit": "ns/op",
            "extra": "104710 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "104710 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "104710 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c6e41a70d1d25b14c4b0995c51e4576f293d7d62",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.31.15 to 1.32.17\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.31.15 to 1.32.17.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.31.15...config/v1.32.17)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.17\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T19:33:23Z",
          "tree_id": "914fbc52939a74ec20834c68ae04e881c98c594c",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/c6e41a70d1d25b14c4b0995c51e4576f293d7d62"
        },
        "date": 1778700836544,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 8900,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "135566 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 8900,
            "unit": "ns/op",
            "extra": "135566 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "135566 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "135566 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "27e4759d64cf8e391eee976cbb0ecb5608b2bd75",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.97.3 to 1.101.0\n\nBumps [github.com/aws/aws-sdk-go-v2/service/s3](https://github.com/aws/aws-sdk-go-v2) from 1.97.3 to 1.101.0.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/s3/v1.97.3...service/s3/v1.101.0)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/s3\n  dependency-version: 1.101.0\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T19:33:45Z",
          "tree_id": "ed1440ddf23da03fa8af5072c06ba0d477e70d20",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/27e4759d64cf8e391eee976cbb0ecb5608b2bd75"
        },
        "date": 1778700870704,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11537,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "102945 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11537,
            "unit": "ns/op",
            "extra": "102945 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "102945 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "102945 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e0c4267de2148253a42752dec969e925bfeb879c",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.97.3 to 1.101.0 (#71)\n\nBumps [github.com/aws/aws-sdk-go-v2/service/s3](https://github.com/aws/aws-sdk-go-v2) from 1.97.3 to 1.101.0.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/s3/v1.97.3...service/s3/v1.101.0)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/s3\n  dependency-version: 1.101.0\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:38:18-04:00",
          "tree_id": "ed1440ddf23da03fa8af5072c06ba0d477e70d20",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/e0c4267de2148253a42752dec969e925bfeb879c"
        },
        "date": 1778701141213,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9293,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127064 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9293,
            "unit": "ns/op",
            "extra": "127064 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127064 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127064 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a441ad9d5be567d9580c437add7554fca11727a5",
          "message": "Bump golang from 1.25.10-alpine3.22 to 1.26.3-alpine3.22 (#69)\n\nBumps golang from 1.25.10-alpine3.22 to 1.26.3-alpine3.22.\n\n---\nupdated-dependencies:\n- dependency-name: golang\n  dependency-version: 1.26.3-alpine3.22\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:38:37-04:00",
          "tree_id": "d89579ad0764f49526831068c1824011450fe60f",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/a441ad9d5be567d9580c437add7554fca11727a5"
        },
        "date": 1778701158140,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9719,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "123927 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9719,
            "unit": "ns/op",
            "extra": "123927 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "123927 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "123927 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c28d25ee1b65810d6f7b3074b6f4670f9c7085d2",
          "message": "Bump alpine from 3.19 to 3.23\n\nBumps alpine from 3.19 to 3.23.\n\n---\nupdated-dependencies:\n- dependency-name: alpine\n  dependency-version: '3.23'\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T19:40:05Z",
          "tree_id": "c0e0fc91caa24db720063f1f0e0396c69206be61",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/c28d25ee1b65810d6f7b3074b6f4670f9c7085d2"
        },
        "date": 1778701253355,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9455,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127795 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9455,
            "unit": "ns/op",
            "extra": "127795 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127795 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127795 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "09f9b1ca9042d72b9616008a959c231239bd330a",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.31.15 to 1.32.17\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.31.15 to 1.32.17.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.31.15...config/v1.32.17)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.17\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-13T19:40:51Z",
          "tree_id": "9701d85bf554931088700f8a88df9f2f6350aa73",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/09f9b1ca9042d72b9616008a959c231239bd330a"
        },
        "date": 1778701296170,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11444,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "107253 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11444,
            "unit": "ns/op",
            "extra": "107253 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "107253 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "107253 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8ba57a9ded5971a73402acbc4fed227f82037ab8",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.31.15 to 1.32.17 (#70)\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.31.15 to 1.32.17.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.31.15...config/v1.32.17)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.17\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:41:14-04:00",
          "tree_id": "9701d85bf554931088700f8a88df9f2f6350aa73",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/8ba57a9ded5971a73402acbc4fed227f82037ab8"
        },
        "date": 1778701318753,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11401,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "105022 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11401,
            "unit": "ns/op",
            "extra": "105022 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "105022 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "105022 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "64e9204b21d7fc73f3e19150d5a4ce1b38c2c659",
          "message": "Bump alpine from 3.19 to 3.23 (#68)\n\nBumps alpine from 3.19 to 3.23.\n\n---\nupdated-dependencies:\n- dependency-name: alpine\n  dependency-version: '3.23'\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:41:54-04:00",
          "tree_id": "e1067e5b38a76bb3be259bdad767e77f9d7cab1f",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/64e9204b21d7fc73f3e19150d5a4ce1b38c2c659"
        },
        "date": 1778701364021,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9331,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "128156 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9331,
            "unit": "ns/op",
            "extra": "128156 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "128156 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "128156 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7df022f45df075b0c480ece0247849fc16449474",
          "message": "Bump codecov/codecov-action from 4 to 6 in /.github/workflows (#67)\n\nBumps [codecov/codecov-action](https://github.com/codecov/codecov-action) from 4 to 6.\n- [Release notes](https://github.com/codecov/codecov-action/releases)\n- [Changelog](https://github.com/codecov/codecov-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/codecov/codecov-action/compare/v4...v6)\n\n---\nupdated-dependencies:\n- dependency-name: codecov/codecov-action\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:42:34-04:00",
          "tree_id": "ab39665885e606ab29458a0b95a5d9f62c0cfbf1",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/7df022f45df075b0c480ece0247849fc16449474"
        },
        "date": 1778701399353,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9388,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126168 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9388,
            "unit": "ns/op",
            "extra": "126168 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126168 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126168 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "68e98d54cf8ccc1365a9df87603be29f65561998",
          "message": "Bump golangci/golangci-lint-action from 8 to 9 in /.github/workflows (#66)\n\nBumps [golangci/golangci-lint-action](https://github.com/golangci/golangci-lint-action) from 8 to 9.\n- [Release notes](https://github.com/golangci/golangci-lint-action/releases)\n- [Commits](https://github.com/golangci/golangci-lint-action/compare/v8...v9)\n\n---\nupdated-dependencies:\n- dependency-name: golangci/golangci-lint-action\n  dependency-version: '9'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:43:17-04:00",
          "tree_id": "aba663afa311595a2005d58cde50df62c49893b9",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/68e98d54cf8ccc1365a9df87603be29f65561998"
        },
        "date": 1778701444908,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9258,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125689 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9258,
            "unit": "ns/op",
            "extra": "125689 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125689 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125689 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d92e47b580ea9547c856af6d6ec11b32e7027ec9",
          "message": "Bump actions/checkout from 5 to 6 in /.github/workflows (#65)\n\nBumps [actions/checkout](https://github.com/actions/checkout) from 5 to 6.\n- [Release notes](https://github.com/actions/checkout/releases)\n- [Changelog](https://github.com/actions/checkout/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/actions/checkout/compare/v5...v6)\n\n---\nupdated-dependencies:\n- dependency-name: actions/checkout\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:43:48-04:00",
          "tree_id": "b875130c303d564abcb822287e19d4352191399a",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/d92e47b580ea9547c856af6d6ec11b32e7027ec9"
        },
        "date": 1778701476696,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9404,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "128150 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9404,
            "unit": "ns/op",
            "extra": "128150 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "128150 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "128150 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "118f69e73486bb7bf4fb5ce20d2b9d136ed3b823",
          "message": "Bump actions/upload-artifact from 5 to 7 in /.github/workflows (#61)\n\nBumps [actions/upload-artifact](https://github.com/actions/upload-artifact) from 5 to 7.\n- [Release notes](https://github.com/actions/upload-artifact/releases)\n- [Commits](https://github.com/actions/upload-artifact/compare/v5...v7)\n\n---\nupdated-dependencies:\n- dependency-name: actions/upload-artifact\n  dependency-version: '7'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-05-13T15:44:32-04:00",
          "tree_id": "674e43f7c9fe584394599380a5e24ae224906c1d",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/118f69e73486bb7bf4fb5ce20d2b9d136ed3b823"
        },
        "date": 1778701513497,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11510,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "101762 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11510,
            "unit": "ns/op",
            "extra": "101762 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "101762 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "101762 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "committer": {
            "email": "julio@julioj.com",
            "name": "Julio Jimenez",
            "username": "juliojimenez"
          },
          "distinct": true,
          "id": "f4dc6f616a2e24f30d632006bc53b21fb1cd2bd2",
          "message": "fix(test): E2E\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T16:01:11-04:00",
          "tree_id": "9156db0c7ded8e75b484fe4bd28c8950b6685f42",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/f4dc6f616a2e24f30d632006bc53b21fb1cd2bd2"
        },
        "date": 1778702521909,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9348,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127765 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9348,
            "unit": "ns/op",
            "extra": "127765 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127765 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127765 times\n4 procs"
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
          "id": "10f76361960f877898b3d087f683e82ec5d66430",
          "message": "fix(test): E2E (#74)\n\nSigned-off-by: Julio Jimenez <julio@julioj.com>",
          "timestamp": "2026-05-13T16:08:06-04:00",
          "tree_id": "9156db0c7ded8e75b484fe4bd28c8950b6685f42",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/10f76361960f877898b3d087f683e82ec5d66430"
        },
        "date": 1778702946377,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9753,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "127280 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9753,
            "unit": "ns/op",
            "extra": "127280 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "127280 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "127280 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "36394d7b1130d1a86fc8defb08d07ec313f624d5",
          "message": "Bump github/codeql-action from 3 to 4 in /.github/workflows\n\nBumps [github/codeql-action](https://github.com/github/codeql-action) from 3 to 4.\n- [Release notes](https://github.com/github/codeql-action/releases)\n- [Changelog](https://github.com/github/codeql-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/github/codeql-action/compare/v3...v4)\n\n---\nupdated-dependencies:\n- dependency-name: github/codeql-action\n  dependency-version: '4'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-18T20:17:59Z",
          "tree_id": "4dbdb74bc23883f6007dd6914f79a21cc64eaca6",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/36394d7b1130d1a86fc8defb08d07ec313f624d5"
        },
        "date": 1779135518778,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11619,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "106059 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11619,
            "unit": "ns/op",
            "extra": "106059 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "106059 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "106059 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a6a0958f4166b8174e65aa7c13698a7080a0531b",
          "message": "Bump actions/setup-go from 5 to 6 in /.github/workflows\n\nBumps [actions/setup-go](https://github.com/actions/setup-go) from 5 to 6.\n- [Release notes](https://github.com/actions/setup-go/releases)\n- [Commits](https://github.com/actions/setup-go/compare/v5...v6)\n\n---\nupdated-dependencies:\n- dependency-name: actions/setup-go\n  dependency-version: '6'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-18T20:18:03Z",
          "tree_id": "c5682de0124b95ca16e4b583535ae707c910456d",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/a6a0958f4166b8174e65aa7c13698a7080a0531b"
        },
        "date": 1779135521459,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 5642,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "202618 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 5642,
            "unit": "ns/op",
            "extra": "202618 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "202618 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "202618 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "71d8b5f5f6b14b852a731d429104d5801b12bc41",
          "message": "Bump docker/setup-buildx-action from 3 to 4 in /.github/workflows\n\nBumps [docker/setup-buildx-action](https://github.com/docker/setup-buildx-action) from 3 to 4.\n- [Release notes](https://github.com/docker/setup-buildx-action/releases)\n- [Commits](https://github.com/docker/setup-buildx-action/compare/v3...v4)\n\n---\nupdated-dependencies:\n- dependency-name: docker/setup-buildx-action\n  dependency-version: '4'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-18T20:18:13Z",
          "tree_id": "2cbeb9d26ce4fab6383c1e151ea0e52768076c86",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/71d8b5f5f6b14b852a731d429104d5801b12bc41"
        },
        "date": 1779135525830,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 8937,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "139119 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 8937,
            "unit": "ns/op",
            "extra": "139119 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "139119 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "139119 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7c7ff75a77dc805475a46a8878d4cfeb0a908b5f",
          "message": "Bump actions/upload-artifact from 4 to 7 in /.github/workflows\n\nBumps [actions/upload-artifact](https://github.com/actions/upload-artifact) from 4 to 7.\n- [Release notes](https://github.com/actions/upload-artifact/releases)\n- [Commits](https://github.com/actions/upload-artifact/compare/v4...v7)\n\n---\nupdated-dependencies:\n- dependency-name: actions/upload-artifact\n  dependency-version: '7'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-18T20:18:10Z",
          "tree_id": "490969197e20e08347afe938f8d011262d987181",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/7c7ff75a77dc805475a46a8878d4cfeb0a908b5f"
        },
        "date": 1779135530938,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11762,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "100768 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11762,
            "unit": "ns/op",
            "extra": "100768 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "100768 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "100768 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "af101d35acc094da7d9cea613f6101c50af034bf",
          "message": "Bump docker/build-push-action from 5 to 7 in /.github/workflows\n\nBumps [docker/build-push-action](https://github.com/docker/build-push-action) from 5 to 7.\n- [Release notes](https://github.com/docker/build-push-action/releases)\n- [Commits](https://github.com/docker/build-push-action/compare/v5...v7)\n\n---\nupdated-dependencies:\n- dependency-name: docker/build-push-action\n  dependency-version: '7'\n  dependency-type: direct:production\n  update-type: version-update:semver-major\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-18T20:18:16Z",
          "tree_id": "e1426fe157302813315f42691f749ef7349f4439",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/af101d35acc094da7d9cea613f6101c50af034bf"
        },
        "date": 1779135539102,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9329,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "129897 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9329,
            "unit": "ns/op",
            "extra": "129897 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "129897 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "129897 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c7e6f2956a19fd1390770320c9754fa1415b172f",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.32.17 to 1.32.18\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.32.17 to 1.32.18.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.32.17...config/v1.32.18)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.18\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-05-25T16:58:52Z",
          "tree_id": "36b45b7edc0484246f7328eccf617461b05fa42e",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/c7e6f2956a19fd1390770320c9754fa1415b172f"
        },
        "date": 1779728369793,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9499,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125748 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9499,
            "unit": "ns/op",
            "extra": "125748 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125748 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125748 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "89a59d2e24f1871305d97ee9cd6c0720326de598",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.32.17 to 1.32.20\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.32.17 to 1.32.20.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.32.17...config/v1.32.20)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.20\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-02T08:38:04Z",
          "tree_id": "480517356c5c6cc299e8fb084bd2c3ca2d7e0c6d",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/89a59d2e24f1871305d97ee9cd6c0720326de598"
        },
        "date": 1780389525639,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9538,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125232 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9538,
            "unit": "ns/op",
            "extra": "125232 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125232 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125232 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "178db1accdc3327bae48fff5f650e40269dbfbf4",
          "message": "Bump github.com/aws/aws-sdk-go-v2 from 1.41.7 to 1.41.9\n\nBumps [github.com/aws/aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) from 1.41.7 to 1.41.9.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/v1.41.7...v1.41.9)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2\n  dependency-version: 1.41.9\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-02T08:39:20Z",
          "tree_id": "135c90d199655eb3469b241eda7ec174ac9e3659",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/178db1accdc3327bae48fff5f650e40269dbfbf4"
        },
        "date": 1780389599929,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9649,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125275 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9649,
            "unit": "ns/op",
            "extra": "125275 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125275 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125275 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1277ca1faa4b17d6f398a3b4332046dd487a3695",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/sts from 1.42.1 to 1.42.3\n\nBumps [github.com/aws/aws-sdk-go-v2/service/sts](https://github.com/aws/aws-sdk-go-v2) from 1.42.1 to 1.42.3.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/s3/v1.42.1...service/amp/v1.42.3)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/sts\n  dependency-version: 1.42.3\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-02T08:40:37Z",
          "tree_id": "b0211791de8aabec90b131be0b55a6dbac6073e3",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/1277ca1faa4b17d6f398a3b4332046dd487a3695"
        },
        "date": 1780389678005,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 5726,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "195022 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 5726,
            "unit": "ns/op",
            "extra": "195022 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "195022 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "195022 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9b5ca40f93cc88f2c851716ce1e335e5ec8f5d47",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.101.0 to 1.102.2\n\nBumps [github.com/aws/aws-sdk-go-v2/service/s3](https://github.com/aws/aws-sdk-go-v2) from 1.101.0 to 1.102.2.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/s3/v1.101.0...service/s3/v1.102.2)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/s3\n  dependency-version: 1.102.2\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-02T08:41:54Z",
          "tree_id": "50b8e71d488583f26bce68645f54607059058792",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/9b5ca40f93cc88f2c851716ce1e335e5ec8f5d47"
        },
        "date": 1780389748607,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 8822,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "133923 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 8822,
            "unit": "ns/op",
            "extra": "133923 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "133923 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "133923 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1c0d797f2c4f88ae6ce9e3d7a3376c18ebbf4370",
          "message": "Bump golang from 1.26.3-alpine3.22 to 1.26.4-alpine3.22\n\nBumps golang from 1.26.3-alpine3.22 to 1.26.4-alpine3.22.\n\n---\nupdated-dependencies:\n- dependency-name: golang\n  dependency-version: 1.26.4-alpine3.22\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-08T11:04:28Z",
          "tree_id": "5abc500df3ea1e9349bca35f0001608ca480e0c5",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/1c0d797f2c4f88ae6ce9e3d7a3376c18ebbf4370"
        },
        "date": 1780916711863,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9578,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "122971 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9578,
            "unit": "ns/op",
            "extra": "122971 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "122971 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "122971 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e8ee46a7d865922b78413fda107e6c19f188a3ce",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/s3 from 1.101.0 to 1.103.2\n\nBumps [github.com/aws/aws-sdk-go-v2/service/s3](https://github.com/aws/aws-sdk-go-v2) from 1.101.0 to 1.103.2.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/s3/v1.101.0...service/s3/v1.103.2)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/s3\n  dependency-version: 1.103.2\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-08T11:08:58Z",
          "tree_id": "8bd265fb0e6ca28221e5f073a6e280192600fd5e",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/e8ee46a7d865922b78413fda107e6c19f188a3ce"
        },
        "date": 1780916976055,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 5475,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "217108 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 5475,
            "unit": "ns/op",
            "extra": "217108 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "217108 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "217108 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "6573a56f3e5e20d3c54dbdf85acadeb4c63ea4a7",
          "message": "Bump github.com/aws/aws-sdk-go-v2 from 1.41.7 to 1.41.12\n\nBumps [github.com/aws/aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) from 1.41.7 to 1.41.12.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/v1.41.7...v1.41.12)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2\n  dependency-version: 1.41.12\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-08T11:09:58Z",
          "tree_id": "7122509d7e63f30daf97439a594cf450e96458ec",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/6573a56f3e5e20d3c54dbdf85acadeb4c63ea4a7"
        },
        "date": 1780917035566,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9541,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "125536 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9541,
            "unit": "ns/op",
            "extra": "125536 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "125536 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "125536 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a0f9bbdfd7d29bbf1b66ac079937e0c27651745d",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.32.17 to 1.32.23\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.32.17 to 1.32.23.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.32.17...config/v1.32.23)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.23\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-08T11:10:58Z",
          "tree_id": "2129af866d01e3602af93abf6259c459bef914c6",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/a0f9bbdfd7d29bbf1b66ac079937e0c27651745d"
        },
        "date": 1780917098555,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9410,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "129032 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9410,
            "unit": "ns/op",
            "extra": "129032 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "129032 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "129032 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "d0714a479e72da17dd2f4150dd4bf57c17bca21b",
          "message": "Bump github.com/aws/aws-sdk-go-v2/service/sts from 1.42.1 to 1.43.2\n\nBumps [github.com/aws/aws-sdk-go-v2/service/sts](https://github.com/aws/aws-sdk-go-v2) from 1.42.1 to 1.43.2.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/service/s3/v1.42.1...service/amp/v1.43.2)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/service/sts\n  dependency-version: 1.43.2\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-08T11:12:00Z",
          "tree_id": "86625612249c48d06d82bb75e2ef5cdd5bda0d4a",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/d0714a479e72da17dd2f4150dd4bf57c17bca21b"
        },
        "date": 1780917160550,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 11310,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "102204 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 11310,
            "unit": "ns/op",
            "extra": "102204 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "102204 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "102204 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9652923fbe808e265ae6f2652695f4ef3d424121",
          "message": "Bump alpine from 3.23 to 3.24\n\nBumps alpine from 3.23 to 3.24.\n\n---\nupdated-dependencies:\n- dependency-name: alpine\n  dependency-version: '3.24'\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-15T11:06:19Z",
          "tree_id": "495b7237cbf61421936147f485394771b9795aa3",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/9652923fbe808e265ae6f2652695f4ef3d424121"
        },
        "date": 1781521625203,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9207,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "126691 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9207,
            "unit": "ns/op",
            "extra": "126691 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "126691 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "126691 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f2bbac7131d065e8460eddd373293f1a9eb793b7",
          "message": "Bump github.com/aws/aws-sdk-go-v2/config from 1.32.17 to 1.32.25\n\nBumps [github.com/aws/aws-sdk-go-v2/config](https://github.com/aws/aws-sdk-go-v2) from 1.32.17 to 1.32.25.\n- [Release notes](https://github.com/aws/aws-sdk-go-v2/releases)\n- [Commits](https://github.com/aws/aws-sdk-go-v2/compare/config/v1.32.17...config/v1.32.25)\n\n---\nupdated-dependencies:\n- dependency-name: github.com/aws/aws-sdk-go-v2/config\n  dependency-version: 1.32.25\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>",
          "timestamp": "2026-06-15T11:10:30Z",
          "tree_id": "890eeceed8fdd25a5728187c3f289214d13d6ab3",
          "url": "https://github.com/ClickHouse/ClickBOM/commit/f2bbac7131d065e8460eddd373293f1a9eb793b7"
        },
        "date": 1781521877797,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkDetectSBOMFormat",
            "value": 9192,
            "unit": "ns/op\t    1152 B/op\t      14 allocs/op",
            "extra": "130602 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - ns/op",
            "value": 9192,
            "unit": "ns/op",
            "extra": "130602 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - B/op",
            "value": 1152,
            "unit": "B/op",
            "extra": "130602 times\n4 procs"
          },
          {
            "name": "BenchmarkDetectSBOMFormat - allocs/op",
            "value": 14,
            "unit": "allocs/op",
            "extra": "130602 times\n4 procs"
          }
        ]
      }
    ]
  }
}