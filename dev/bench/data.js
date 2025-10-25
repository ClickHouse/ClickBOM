window.BENCHMARK_DATA = {
  "lastUpdate": 1761429217261,
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
      }
    ]
  }
}