// Package storage provides functionalities to interact with storage backends like S3.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ClickHouse/ClickBOM/pkg/logger"
)

// bucketRegionHeader is the response header S3 uses to advertise a bucket's
// home region. It is present on successful HeadBucket responses and also on
// the 301 PermanentRedirect / 403 responses S3 sends when a request reaches
// the wrong regional endpoint.
const bucketRegionHeader = "x-amz-bucket-region"

// bucketRegionResolver looks up the AWS region that hosts a bucket. It is a
// package-level variable so unit tests can substitute a fake without talking
// to S3.
var bucketRegionResolver = resolveBucketRegion

// resolveBucketRegion issues a HeadBucket against the default regional
// endpoint and reads the bucket's region from the response. Because S3
// includes x-amz-bucket-region on error responses too, a 301 (wrong region)
// or 403 (no s3:ListBucket permission) still yields the answer; only a
// response without the header (e.g. 404 NoSuchBucket) is an error.
func resolveBucketRegion(ctx context.Context, client *s3.Client, bucket string) (string, error) {
	out, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	if err == nil {
		return aws.ToString(out.BucketRegion), nil
	}

	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) && respErr.Response != nil {
		if region := respErr.Response.Header.Get(bucketRegionHeader); region != "" {
			return region, nil
		}
	}
	return "", err
}

// S3Client handles interactions with Amazon S3.
type S3Client struct {
	awsCfg aws.Config
	// defaultClient is bound to the region from the SDK default chain
	// (AWS_REGION / AWS_DEFAULT_REGION / shared config).
	defaultClient *s3.Client
	// customEndpoint is true when AWS_ENDPOINT_URL (or AWS_ENDPOINT_URL_S3)
	// points at a non-AWS S3-compatible endpoint such as MinIO or LocalStack.
	// Region discovery is skipped in that case: there is only one endpoint.
	customEndpoint bool

	mu            sync.Mutex
	regionClients map[string]*s3.Client // region -> client bound to that region
	bucketRegions map[string]string     // bucket -> resolved region
}

// NewS3Client creates a new S3Client using the AWS SDK default credential and
// region chain (environment, shared config, IMDS, ...).
func NewS3Client(ctx context.Context) (*S3Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	customEndpoint := os.Getenv("AWS_ENDPOINT_URL") != "" || os.Getenv("AWS_ENDPOINT_URL_S3") != ""

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		// S3-compatible stores generally do not support virtual-hosted-style
		// addressing (bucket.host:port); path-style is the interoperable choice.
		if customEndpoint {
			o.UsePathStyle = true
		}
	})

	return &S3Client{
		awsCfg:         cfg,
		defaultClient:  client,
		customEndpoint: customEndpoint,
		regionClients:  map[string]*s3.Client{},
		bucketRegions:  map[string]string{},
	}, nil
}

// clientFor returns an S3 client bound to the region that hosts bucket.
//
// S3 buckets are regional and S3 rejects requests sent to the wrong regional
// endpoint with 301 PermanentRedirect ("The bucket you are attempting to access
// must be addressed using the specified endpoint"). The AWS CLI used by the
// bash version of this action followed that redirect transparently; the SDK
// does not. To keep the action usable when the job's AWS_REGION differs from
// the bucket's region, we resolve the bucket's region once and cache a client
// per region. On lookup failure we fall back to the default-region client so a
// missing s3:ListBucket permission never blocks an otherwise valid request.
func (s *S3Client) clientFor(ctx context.Context, bucket string) *s3.Client {
	if s.customEndpoint {
		return s.defaultClient
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	region, known := s.bucketRegions[bucket]
	if !known {
		resolved, err := bucketRegionResolver(ctx, s.defaultClient, bucket)
		switch {
		case err != nil:
			logger.Warning("Could not determine region for bucket %s (%v); using default region %q", bucket, err, s.awsCfg.Region)
			resolved = s.awsCfg.Region
		case resolved == "":
			resolved = s.awsCfg.Region
		}
		region = resolved
		s.bucketRegions[bucket] = region
	}

	if region == "" || region == s.awsCfg.Region {
		return s.defaultClient
	}
	if c, ok := s.regionClients[region]; ok {
		return c
	}

	logger.Info("Bucket %s is in region %s (default region %q); using a region-specific client", bucket, region, s.awsCfg.Region)
	c := s3.NewFromConfig(s.awsCfg, func(o *s3.Options) {
		o.Region = region
	})
	s.regionClients[region] = c
	return c
}

// Upload uploads a file to the specified S3 bucket and key.
func (s *S3Client) Upload(ctx context.Context, localFile, bucket, key, sbomFormat string) error {
	logger.Info("Uploading %s SBOM to s3://%s/%s", sbomFormat, bucket, key)

	file, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warning("Failed to close file: %v", err)
		}
	}()

	contentType := "application/json"

	_, err = s.clientFor(ctx, bucket).PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        file,
		ContentType: aws.String(contentType),
		Metadata: map[string]string{
			"format": sbomFormat,
			"source": "github-action",
		},
	})

	if err != nil {
		return fmt.Errorf("failed to upload SBOM to S3: %w", err)
	}

	logger.Success("SBOM uploaded successfully to S3")
	return nil
}

// Download downloads a file from the specified S3 bucket and key to a local file.
func (s *S3Client) Download(ctx context.Context, bucket, key, localFile string) error {
	logger.Debug("Downloading s3://%s/%s to %s", bucket, key, localFile)

	result, err := s.clientFor(ctx, bucket).GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to download from S3: %w", err)
	}
	defer func() {
		if err := result.Body.Close(); err != nil {
			logger.Warning("Failed to close response body: %v", err)
		}
	}()

	file, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Warning("Failed to close file: %v", err)
		}
	}()

	_, err = io.Copy(file, result.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ListObjects lists the object keys in the specified S3 bucket with the given prefix.
func (s *S3Client) ListObjects(ctx context.Context, bucket, prefix string) ([]string, error) {
	logger.Debug("Listing objects in s3://%s with prefix: %s", bucket, prefix)

	var keys []string

	paginator := s3.NewListObjectsV2Paginator(s.clientFor(ctx, bucket), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range page.Contents {
			keys = append(keys, *obj.Key)
		}
	}

	logger.Info("Found %d objects in S3", len(keys))
	return keys, nil
}

// DownloadAll downloads all files from S3 bucket to local directory.
func (s *S3Client) DownloadAll(ctx context.Context, bucket, prefix, localDir string) ([]string, error) {
	logger.Info("Downloading all files from s3://%s/%s", bucket, prefix)

	// List all objects
	keys, err := s.ListObjects(ctx, bucket, prefix)
	if err != nil {
		return nil, err
	}

	downloadedFiles := make([]string, 0)

	for _, key := range keys {
		// Skip directories (keys ending with /)
		if strings.HasSuffix(key, "/") {
			continue
		}

		localPath := filepath.Join(localDir, localFilenameForKey(key))

		if err := s.Download(ctx, bucket, key, localPath); err != nil {
			logger.Warning("Failed to download %s: %v", key, err)
			continue
		}

		downloadedFiles = append(downloadedFiles, localPath)
	}

	logger.Info("Downloaded %d files", len(downloadedFiles))
	return downloadedFiles, nil
}

// localFilenameForKey flattens an S3 key into a single filename safe for the
// download directory, preserving enough of the key structure that two objects
// sharing a basename (`teamA/sbom.json`, `teamB/sbom.json`) don't collide.
// Leading underscores are trimmed so the result doesn't start with one when
// the key has a leading slash.
func localFilenameForKey(key string) string {
	return strings.TrimLeft(strings.ReplaceAll(key, "/", "_"), "_")
}
