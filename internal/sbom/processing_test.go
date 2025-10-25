package sbom

import (
    "os"
    "testing"
)

func BenchmarkDetectSBOMFormat(b *testing.B) {
    // Create test SBOM file
    testFile := "/tmp/bench-sbom.json"
    testContent := []byte(`{
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": []
    }`)
    if err := os.WriteFile(testFile, testContent, 0644); err != nil {
        b.Fatalf("Failed to create test file: %v", err)
    }
    defer os.Remove(testFile)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := DetectSBOMFormat(testFile)
        if err != nil {
            b.Fatalf("DetectSBOMFormat failed: %v", err)
        }
    }
}
