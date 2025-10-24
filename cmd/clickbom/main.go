package main

import (
    "context"
    "fmt"
    "os"
    
    "github.com/ClickHouse/ClickBOM/internal/config"
    "github.com/ClickHouse/ClickBOM/internal/sbom"
    "github.com/ClickHouse/ClickBOM/internal/storage"
    "github.com/ClickHouse/ClickBOM/pkg/logger"
)

func main() {
    if err := run(); err != nil {
        logger.Fatal("Application error: %v", err)
    }
}

func run() error {
    logger.Info("Starting ClickBOM GitHub Action for SBOM processing")
    
    // Load and validate configuration
    cfg, err := config.LoadConfig()
    if err != nil {
        return fmt.Errorf("configuration error: %w", err)
    }
    
    logger.SetDebug(cfg.Debug)
    
    ctx := context.Background()
    
    // Create temp directory
    tempDir, err := os.MkdirTemp("", "clickbom-*")
    if err != nil {
        return fmt.Errorf("failed to create temp directory: %w", err)
    }
    defer os.RemoveAll(tempDir)
    
    // Initialize S3 client
    s3Client, err := storage.NewS3Client(ctx, cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSRegion)
    if err != nil {
        return fmt.Errorf("failed to create S3 client: %w", err)
    }
    
    if cfg.Merge {
        return handleMergeMode(ctx, cfg, s3Client, tempDir)
    }
    
    return handleNormalMode(ctx, cfg, s3Client, tempDir)
}

func handleNormalMode(ctx context.Context, cfg *config.Config, s3Client *storage.S3Client, tempDir string) error {
    logger.Info("Running in NORMAL mode - processing SBOM from %s", cfg.SBOMSource)
    
    originalSBOM := filepath.Join(tempDir, "original_sbom.json")
    extractedSBOM := filepath.Join(tempDir, "extracted_sbom.json")
    processedSBOM := filepath.Join(tempDir, "processed_sbom.json")
    
    // Download SBOM based on source
    switch cfg.SBOMSource {
    case "github":
        logger.Info("Downloading SBOM from GitHub")
        ghClient := sbom.NewGitHubClient(cfg.GitHubToken)
        if err := ghClient.DownloadSBOM(ctx, cfg.Repository, originalSBOM); err != nil {
            return fmt.Errorf("failed to download GitHub SBOM: %w", err)
        }
        
    case "mend":
        logger.Info("Downloading SBOM from Mend")
        mendClient := sbom.NewMendClient(cfg)
        if err := mendClient.RequestSBOMExport(ctx, originalSBOM); err != nil {
            return fmt.Errorf("failed to download Mend SBOM: %w", err)
        }
        
    case "wiz":
        logger.Info("Downloading SBOM from Wiz")
        wizClient := sbom.NewWizClient(cfg)
        if err := wizClient.DownloadReport(ctx, originalSBOM); err != nil {
            return fmt.Errorf("failed to download Wiz SBOM: %w", err)
        }
        
    default:
        return fmt.Errorf("unsupported SBOM source: %s", cfg.SBOMSource)
    }
    
    // Extract from wrapper if needed
    if err := sbom.ExtractSBOMFromWrapper(originalSBOM, extractedSBOM); err != nil {
        return fmt.Errorf("failed to extract SBOM: %w", err)
    }
    
    // Detect format
    detectedFormat, err := sbom.DetectSBOMFormat(extractedSBOM)
    if err != nil {
        return fmt.Errorf("failed to detect SBOM format: %w", err)
    }
    logger.Info("Detected SBOM format: %s", detectedFormat)
    
    // Convert to desired format
    targetFormat := sbom.SBOMFormat(cfg.SBOMFormat)
    if err := sbom.ConvertSBOM(extractedSBOM, processedSBOM, detectedFormat, targetFormat); err != nil {
        return fmt.Errorf("failed to convert SBOM: %w", err)
    }
    
    // Upload to S3
    if err := s3Client.Upload(ctx, processedSBOM, cfg.S3Bucket, cfg.S3Key, cfg.SBOMFormat); err != nil {
        return fmt.Errorf("failed to upload to S3: %w", err)
    }
    
    logger.Success("SBOM processing completed successfully!")
    logger.Info("SBOM available at: s3://%s/%s", cfg.S3Bucket, cfg.S3Key)
    
    // ClickHouse operations
    if cfg.ClickHouseURL != "" {
        if err := handleClickHouse(ctx, cfg, processedSBOM); err != nil {
            return fmt.Errorf("ClickHouse error: %w", err)
        }
    }
    
    return nil
}

func handleMergeMode(ctx context.Context, cfg *config.Config, s3Client *storage.S3Client, tempDir string) error {
    logger.Info("Running in MERGE mode - merging all CycloneDX SBOMs from S3")
    
    // Implementation for merge mode...
    // This would involve downloading all SBOMs from S3, merging them, and uploading
    
    return nil
}

func handleClickHouse(ctx context.Context, cfg *config.Config, sbomFile string) error {
    logger.Info("Starting ClickHouse operations")
    
    chClient, err := storage.NewClickHouseClient(cfg)
    if err != nil {
        return err
    }
    
    tableName := generateTableName(cfg)
    
    if err := chClient.SetupTable(ctx, tableName); err != nil {
        return fmt.Errorf("failed to setup table: %w", err)
    }
    
    if err := chClient.InsertSBOMData(ctx, sbomFile, tableName, cfg.SBOMFormat); err != nil {
        return fmt.Errorf("failed to insert data: %w", err)
    }
    
    logger.Success("ClickHouse operations completed successfully!")
    return nil
}

func generateTableName(cfg *config.Config) string {
    switch cfg.SBOMSource {
    case "github":
        return strings.ReplaceAll(strings.ToLower(cfg.Repository), "/", "_")
    case "mend":
        uuid := cfg.MendProjectUUID
        if uuid == "" {
            uuid = cfg.MendProductUUID
        }
        return fmt.Sprintf("mend_%s", strings.ReplaceAll(uuid, "-", "_"))
    case "wiz":
        return fmt.Sprintf("wiz_%s", strings.ReplaceAll(cfg.WizReportID, "-", "_"))
    default:
        return "sbom_data"
    }
}
