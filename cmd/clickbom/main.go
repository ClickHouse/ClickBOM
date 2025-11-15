// Package main implements the ClickBOM GitHub Action for SBOM processing.
package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

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
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			logger.Warning("Failed to remove temp directory: %v", err)
		}
	}()

	// Initialize S3 client
	s3Client, err := storage.NewS3Client(ctx)
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

	// Download/Generate SBOM based on source
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

	case "trivy":
		logger.Info("Generating SBOM with Trivy")
		trivyClient, err := sbom.NewTrivyClient(ctx, cfg)
		if err != nil {
			return fmt.Errorf("failed to create Trivy client: %w", err)
		}
		if err := trivyClient.GenerateSBOM(ctx, originalSBOM); err != nil {
			return fmt.Errorf("failed to generate SBOM with Trivy: %w", err)
		}

	default:
		return fmt.Errorf("unsupported SBOM source: %s", cfg.SBOMSource)
	}

	// Extract SBOM from wrapper if needed (mainly for GitHub)
	if err := sbom.ExtractSBOMFromWrapper(originalSBOM, extractedSBOM); err != nil {
		return fmt.Errorf("failed to extract SBOM: %w", err)
	}

	// Detect format
	detectedFormat, err := sbom.DetectSBOMFormat(extractedSBOM)
	if err != nil {
		return fmt.Errorf("failed to detect SBOM format: %w", err)
	}
	logger.Info("Detected SBOM format: %s", detectedFormat)

	// Convert to desired format if needed
	desiredFormat := sbom.Format(cfg.SBOMFormat)
	if err := sbom.ConvertSBOM(extractedSBOM, processedSBOM, detectedFormat, desiredFormat); err != nil {
		return fmt.Errorf("failed to convert SBOM: %w", err)
	}

	// Upload to S3
	if err := s3Client.Upload(ctx, processedSBOM, cfg.S3Bucket, cfg.S3Key, cfg.SBOMFormat); err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	logger.Success("SBOM processing completed successfully!")

	// ClickHouse upload if configured
	if cfg.ClickHouseURL != "" {
		logger.Info("Uploading SBOM data to ClickHouse")

		chClient, err := storage.NewClickHouseClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to create ClickHouse client: %w", err)
		}

		tableName := generateTableName(cfg)

		if err := chClient.SetupTable(ctx, tableName); err != nil {
			return fmt.Errorf("failed to setup table: %w", err)
		}

		if err := chClient.InsertSBOMData(ctx, processedSBOM, tableName, cfg.SBOMFormat); err != nil {
			return fmt.Errorf("failed to upload to ClickHouse: %w", err)
		}

		logger.Success("ClickHouse operations completed successfully!")
	}

	return nil
}

func handleMergeMode(ctx context.Context, cfg *config.Config, s3Client *storage.S3Client, tempDir string) error {
	logger.Info("Running in MERGE mode - merging all CycloneDX SBOMs from S3")

	// Create download directory
	downloadDir := filepath.Join(tempDir, "downloads")
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return fmt.Errorf("failed to create download directory: %w", err)
	}

	// Download all files from S3
	downloadedFiles, err := s3Client.DownloadAll(ctx, cfg.S3Bucket, "", downloadDir)
	if err != nil {
		return fmt.Errorf("failed to download files from S3: %w", err)
	}

	logger.Info("Downloaded %d files from S3", len(downloadedFiles))

	if len(downloadedFiles) == 0 {
		return fmt.Errorf("no files found in S3 bucket: %s", cfg.S3Bucket)
	}

	// Filter and validate CycloneDX SBOMs
	cyclonedxFiles := make([]string, 0)

	for _, file := range downloadedFiles {
		filename := filepath.Base(file)

		// Apply include/exclude filters
		if !sbom.ShouldIncludeFile(filename, cfg.Include, cfg.Exclude) {
			logger.Debug("Skipping %s due to include/exclude filters", filename)
			continue
		}

		// Check if file is valid CycloneDX
		format, err := sbom.DetectSBOMFormat(file)
		if err != nil {
			logger.Warning("Failed to detect format for %s: %v", filename, err)
			continue
		}

		if format != sbom.FormatCycloneDX {
			logger.Debug("Skipping %s: not CycloneDX format (detected: %s)", filename, format)
			continue
		}

		cyclonedxFiles = append(cyclonedxFiles, file)
		logger.Debug("Added %s to merge list", filename)
	}

	logger.Info("Found %d valid CycloneDX SBOMs to merge", len(cyclonedxFiles))

	if len(cyclonedxFiles) == 0 {
		return fmt.Errorf("no valid CycloneDX SBOMs found after filtering")
	}

	// Merge all SBOMs
	mergedSBOM := filepath.Join(tempDir, "merged_sbom.json")
	if err := sbom.MergeSBOMs(cyclonedxFiles, mergedSBOM); err != nil {
		return fmt.Errorf("failed to merge SBOMs: %w", err)
	}

	// Convert to desired format if needed
	finalSBOM := filepath.Join(tempDir, "final_sbom.json")
	desiredFormat := sbom.Format(cfg.SBOMFormat)
	if err := sbom.ConvertSBOM(mergedSBOM, finalSBOM, sbom.FormatCycloneDX, desiredFormat); err != nil {
		return fmt.Errorf("failed to convert merged SBOM: %w", err)
	}

	// Upload merged SBOM back to S3
	if err := s3Client.Upload(ctx, finalSBOM, cfg.S3Bucket, cfg.S3Key, cfg.SBOMFormat); err != nil {
		return fmt.Errorf("failed to upload merged SBOM: %w", err)
	}

	logger.Success("SBOM merging and upload completed successfully!")

	// ClickHouse upload if configured
	if cfg.ClickHouseURL != "" {
		logger.Info("Uploading merged SBOM data to ClickHouse")

		chClient, err := storage.NewClickHouseClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to create ClickHouse client: %w", err)
		}

		tableName := generateTableName(cfg)

		if err := chClient.SetupTable(ctx, tableName); err != nil {
			return fmt.Errorf("failed to setup table: %w", err)
		}

		if err := chClient.InsertSBOMData(ctx, finalSBOM, tableName, cfg.SBOMFormat); err != nil {
			return fmt.Errorf("failed to upload to ClickHouse: %w", err)
		}

		logger.Success("ClickHouse operations completed successfully!")
	}

	return nil
}

func handleClickHouse(ctx context.Context, cfg *config.Config, sbomFile string) error { // nolint: unused
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
	if cfg.Merge {
		return strings.ReplaceAll(cfg.S3Key, ".", "_")
	}
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
	case "trivy":
		result := path.Base(cfg.TrivyImage)
		replacer := strings.NewReplacer(":", "_", ".", "_", "-", "_")
		result = replacer.Replace(result)
		return fmt.Sprintf("trivy_%s", result)
	default:
		return "sbom_data"
	}
}
