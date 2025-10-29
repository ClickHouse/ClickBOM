// Package sbom provides functionalities to interact with Trivy for SBOM generation.
package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	cfg "github.com/ClickHouse/ClickBOM/internal/config"
	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// TrivyClient handles interactions with Trivy for SBOM generation from container images.
type TrivyClient struct {
	image        string
	ecrAccountID string
	ecrRegion    string
	ecrRoleARN   string
	format       string // "cyclonedx" or "spdxjson"
	awsConfig    aws.Config
}

// NewTrivyClient creates a new TrivyClient with the provided configuration.
func NewTrivyClient(ctx context.Context, c *cfg.Config) (*TrivyClient, error) {
	// Load default AWS config
	awsConfig, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(c.AWSRegion),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			c.AWSAccessKeyID,
			c.AWSSecretAccessKey,
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &TrivyClient{
		image:        c.TrivyImage,
		ecrAccountID: c.TrivyECRAccountID,
		ecrRegion:    c.TrivyECRRegion,
		ecrRoleARN:   c.TrivyECRRoleARN,
		format:       c.TrivyFormat,
		awsConfig:    awsConfig,
	}, nil
}

// setupECRCredentials sets up AWS credentials for ECR access, supporting cross-account.
func (t *TrivyClient) setupECRCredentials(ctx context.Context) error {
	logger.Info("Setting up ECR credentials...")

	var awsConfig aws.Config
	var err error

	// If cross-account role is specified, assume the role
	if t.ecrRoleARN != "" {
		logger.Info("Using cross-account role: %s", t.ecrRoleARN)

		// Create STS client with original credentials
		stsClient := sts.NewFromConfig(t.awsConfig)

		// Assume the role
		assumeRoleOutput, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(t.ecrRoleARN),
			RoleSessionName: aws.String(fmt.Sprintf("trivy-sbom-gen-%d", time.Now().Unix())),
		})
		if err != nil {
			return fmt.Errorf("failed to assume role %s: %w", t.ecrRoleARN, err)
		}

		logger.Success("Successfully assumed cross-account role")

		// Create new config with assumed role credentials
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(t.ecrRegion),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				*assumeRoleOutput.Credentials.AccessKeyId,
				*assumeRoleOutput.Credentials.SecretAccessKey,
				*assumeRoleOutput.Credentials.SessionToken,
			)),
		)
		if err != nil {
			return fmt.Errorf("failed to create config with assumed role credentials: %w", err)
		}
	} else {
		// Use original credentials but with ECR region
		awsConfig, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(t.ecrRegion),
			config.WithCredentialsProvider(t.awsConfig.Credentials),
		)
		if err != nil {
			return fmt.Errorf("failed to create ECR config: %w", err)
		}
	}

	// Retrieve credentials and set environment variables for Trivy
	creds, err := awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	// Trivy will use these AWS credentials directly for ECR authentication
	// No Docker needed!
	err = os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
	if err != nil {
		return fmt.Errorf("failed to set AWS_ACCESS_KEY_ID: %w", err)
	}
	err = os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	if err != nil {
		return fmt.Errorf("failed to set AWS_SECRET_ACCESS_KEY: %w", err)
	}
	if creds.SessionToken != "" {
		err = os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
		if err != nil {
			return fmt.Errorf("failed to set AWS_SESSION_TOKEN: %w", err)
		}
	}
	err = os.Setenv("AWS_REGION", t.ecrRegion)
	if err != nil {
		return fmt.Errorf("failed to set AWS_REGION: %w", err)
	}

	logger.Success("ECR credentials configured for Trivy")
	return nil
}

// GenerateSBOM generates an SBOM from the container image using Trivy.
func (t *TrivyClient) GenerateSBOM(ctx context.Context, outputFile string) error {
	logger.Info("Generating SBOM for image: %s", t.image)
	logger.Info("SBOM format: %s", t.format)
	logger.Info("Using remote image source (no download)")

	// Check if this is an ECR image
	isECRImage := strings.Contains(t.image, ".dkr.ecr.") && strings.Contains(t.image, ".amazonaws.com/")

	// Set up ECR credentials if needed
	// Trivy supports ECR authentication natively without Docker!
	if isECRImage && t.ecrAccountID != "" {
		if err := t.setupECRCredentials(ctx); err != nil {
			return fmt.Errorf("failed to setup ECR credentials: %w", err)
		}
	}

	// Create temp file for raw Trivy output
	tempDir := filepath.Dir(outputFile)
	trivyOutputFile := filepath.Join(tempDir, "trivy_sbom_output.json")

	logger.Info("Running Trivy SBOM generation...")

	// Determine Trivy output format
	var trivyFormat string
	switch t.format {
	case "cyclonedx": // nolint: goconst
		trivyFormat = "cyclonedx"
	case "spdxjson":
		trivyFormat = "spdx-json"
	default:
		return fmt.Errorf("unsupported SBOM format: %s", t.format)
	}

	// Build Trivy command for SBOM generation
	// Using --image-src remote to scan at source without downloading
	args := []string{
		"image",
		"--format", trivyFormat,
		"--output", trivyOutputFile,
		"--image-src", "remote",
		"--quiet",
		t.image,
	}

	cmd := exec.CommandContext(ctx, "trivy", args...)

	// Trivy will use AWS credentials from environment for ECR access
	cmd.Env = os.Environ()

	logger.Debug("Executing: trivy %s", strings.Join(args, " "))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy SBOM generation failed: %w\nOutput: %s", err, string(output))
	}

	logger.Success("Trivy SBOM generation completed successfully")

	// Validate the output
	trivyData, err := os.ReadFile(trivyOutputFile)
	if err != nil {
		return fmt.Errorf("failed to read Trivy output: %w", err)
	}

	var sbomData map[string]interface{}
	if err := json.Unmarshal(trivyData, &sbomData); err != nil {
		return fmt.Errorf("trivy output is not valid JSON: %w", err)
	}

	// Move to final output location
	if err := os.Rename(trivyOutputFile, outputFile); err != nil {
		return fmt.Errorf("failed to move SBOM file: %w", err)
	}

	logger.Info("SBOM saved to: %s", outputFile)

	// Log component count based on format
	switch t.format {
	case "cyclonedx":
		if components, ok := sbomData["components"].([]interface{}); ok {
			logger.Info("Total components found: %d", len(components))
		}
	case "spdxjson":
		if packages, ok := sbomData["packages"].([]interface{}); ok {
			logger.Info("Total packages found: %d", len(packages))
		}
	}

	return nil
}
