// Package main implements the ClickBOM GitHub Action for SBOM processing.
package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	fixedSBOM := filepath.Join(tempDir, "fixed_sbom.json")
	processedSBOM := filepath.Join(tempDir, "processed_sbom.json")

	// Download/Generate SBOM based on source
	switch cfg.SBOMSource {
	case config.SourceGitHub:
		logger.Info("Downloading SBOM from GitHub")
		ghClient := sbom.NewGitHubClient(cfg.GitHubToken)
		if err := ghClient.DownloadSBOM(ctx, cfg.Repository, originalSBOM); err != nil {
			return fmt.Errorf("failed to download GitHub SBOM: %w", err)
		}

	case config.SourceMend:
		logger.Info("Downloading SBOM from Mend")
		mendClient := sbom.NewMendClient(cfg)
		if err := mendClient.RequestSBOMExport(ctx, originalSBOM); err != nil {
			return fmt.Errorf("failed to download Mend SBOM: %w", err)
		}

	case config.SourceWiz:
		logger.Info("Downloading SBOM from Wiz")
		wizClient := sbom.NewWizClient(cfg)
		if err := wizClient.DownloadReport(ctx, originalSBOM); err != nil {
			return fmt.Errorf("failed to download Wiz SBOM: %w", err)
		}

	case config.SourceTrivy:
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

	// SPDX inputs include referenceCategory values (e.g. "PACKAGE-MANAGER") that
	// cyclonedx-cli rejects; normalize them before conversion.
	preConversionSBOM := extractedSBOM
	if detectedFormat == sbom.FormatSPDXJSON {
		if err := sbom.FixSPDXCompatibility(extractedSBOM, fixedSBOM); err != nil {
			return fmt.Errorf("failed to fix SPDX compatibility: %w", err)
		}
		preConversionSBOM = fixedSBOM
	}

	// Convert to desired format if needed
	desiredFormat := sbom.Format(cfg.SBOMFormat)
	if err := sbom.ConvertSBOM(preConversionSBOM, processedSBOM, detectedFormat, desiredFormat); err != nil {
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

		if err := chClient.InsertSBOMData(ctx, processedSBOM, tableName, cfg.SBOMFormat, defaultSourceForConfig(cfg)); err != nil {
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

	// List bucket contents, pre-filter, then download only the keepers. This
	// matches bash's `aws s3 ls | grep '\.json$' | grep -v <target>` pipeline:
	// we avoid pulling non-JSON objects, and we never re-merge the previous
	// merged-output file back into itself.
	allKeys, err := s3Client.ListObjects(ctx, cfg.S3Bucket, "")
	if err != nil {
		return fmt.Errorf("failed to list files in S3: %w", err)
	}

	candidateKeys := selectMergeCandidates(allKeys, cfg)
	if len(candidateKeys) == 0 {
		return fmt.Errorf("no candidate .json files in S3 bucket: %s", cfg.S3Bucket)
	}

	// Download the survivors.
	downloadedFiles := make([]string, 0, len(candidateKeys))
	for _, key := range candidateKeys {
		localPath := filepath.Join(downloadDir, filepath.Base(key))
		if err := s3Client.Download(ctx, cfg.S3Bucket, key, localPath); err != nil {
			logger.Warning("Failed to download %s: %v", key, err)
			continue
		}
		downloadedFiles = append(downloadedFiles, localPath)
	}
	logger.Info("Downloaded %d files from S3", len(downloadedFiles))

	if len(downloadedFiles) == 0 {
		return fmt.Errorf("no files downloaded from S3 bucket: %s", cfg.S3Bucket)
	}

	// Format-validate each candidate: only CycloneDX inputs make it into the merge.
	cyclonedxFiles := make([]string, 0, len(downloadedFiles))
	for _, file := range downloadedFiles {
		filename := filepath.Base(file)
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

		// Merge mode: each component is already tagged with its origin source by
		// MergeSBOMs, so we leave defaultSource empty.
		if err := chClient.InsertSBOMData(ctx, finalSBOM, tableName, cfg.SBOMFormat, ""); err != nil {
			return fmt.Errorf("failed to upload to ClickHouse: %w", err)
		}

		logger.Success("ClickHouse operations completed successfully!")
	}

	return nil
}

// selectMergeCandidates pre-filters a flat list of S3 keys before any download.
// Drops "directory" markers, non-.json files, the merge output target itself,
// and entries excluded by the configured include/exclude patterns.
func selectMergeCandidates(allKeys []string, cfg *config.Config) []string {
	targetBasename := filepath.Base(cfg.S3Key)
	out := make([]string, 0, len(allKeys))
	for _, key := range allKeys {
		if strings.HasSuffix(key, "/") {
			continue
		}
		filename := filepath.Base(key)
		if !strings.HasSuffix(strings.ToLower(filename), ".json") {
			logger.Debug("Skipping %s: not a .json file", filename)
			continue
		}
		if filename == targetBasename {
			logger.Debug("Skipping %s: it is the merge output target", filename)
			continue
		}
		if !sbom.ShouldIncludeFile(filename, cfg.Include, cfg.Exclude) {
			logger.Debug("Skipping %s due to include/exclude filters", filename)
			continue
		}
		out = append(out, key)
	}
	return out
}

// defaultSourceForConfig returns the value to use for the ClickHouse `source`
// column when an SBOM component does not carry its own per-component source
// field (which only happens in merge mode). Matches the bash entrypoint's
// `default_source_value` derivation.
func defaultSourceForConfig(cfg *config.Config) string {
	switch cfg.SBOMSource {
	case config.SourceGitHub:
		if cfg.Repository != "" {
			return cfg.Repository
		}
	case config.SourceMend:
		uuid := cfg.MendProjectUUID
		if uuid == "" {
			uuid = cfg.MendProductUUID
		}
		if uuid == "" {
			uuid = cfg.MendOrgScopeUUID
		}
		if uuid != "" {
			return config.SourceMend + ":" + uuid
		}
		return config.SourceMend + ":unknown"
	case config.SourceWiz:
		if cfg.WizReportID != "" {
			return config.SourceWiz + ":" + cfg.WizReportID
		}
		return config.SourceWiz + ":unknown"
	case config.SourceTrivy:
		if cfg.TrivyImage != "" {
			return config.SourceTrivy + ":" + cfg.TrivyImage
		}
		return config.SourceTrivy + ":unknown"
	}
	return cfg.SBOMSource
}

// tableNameSanitizeRE matches the bash pipeline `sed 's|[^a-zA-Z0-9]|_|g'`:
// every non-alphanumeric run is collapsed to underscores. Compiled once at
// package init.
var tableNameSanitizeRE = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// sanitizeForTableName applies the bash table-name normalization: replace any
// run of non-alphanumerics with `_`, then lowercase. Used by both merge and
// non-merge branches of generateTableName.
func sanitizeForTableName(s string) string {
	return strings.ToLower(tableNameSanitizeRE.ReplaceAllString(s, "_"))
}

func generateTableName(cfg *config.Config) string {
	if cfg.Merge {
		// Strip the trailing extension first so the suffix lands cleanly:
		// `clickbom.json` -> `clickbom_merged`, not `clickbom_json_merged`.
		base := strings.TrimSuffix(cfg.S3Key, filepath.Ext(cfg.S3Key))
		return fmt.Sprintf("%s_merged", sanitizeForTableName(base))
	}
	switch cfg.SBOMSource {
	case config.SourceGitHub:
		return sanitizeForTableName(cfg.Repository)
	case config.SourceMend:
		uuid := cfg.MendProjectUUID
		if uuid == "" {
			uuid = cfg.MendProductUUID
		}
		return fmt.Sprintf("%s_%s", config.SourceMend, sanitizeForTableName(uuid))
	case config.SourceWiz:
		return fmt.Sprintf("%s_%s", config.SourceWiz, sanitizeForTableName(cfg.WizReportID))
	case config.SourceTrivy:
		return fmt.Sprintf("%s_%s", config.SourceTrivy, sanitizeForTableName(path.Base(cfg.TrivyImage)))
	default:
		return "sbom_data"
	}
}
