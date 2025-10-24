package storage

import (
    "context"
    "fmt"
    "os"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    
    "github.com/ClickHouse/ClickBOM/pkg/logger"
)

type S3Client struct {
    client *s3.Client
}

func NewS3Client(ctx context.Context, accessKeyID, secretAccessKey, region string) (*S3Client, error) {
    cfg, err := config.LoadDefaultConfig(ctx,
        config.WithRegion(region),
        config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
            accessKeyID,
            secretAccessKey,
            "",
        )),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to load AWS config: %w", err)
    }
    
    return &S3Client{
        client: s3.NewFromConfig(cfg),
    }, nil
}

func (s *S3Client) Upload(ctx context.Context, localFile, bucket, key, sbomFormat string) error {
    logger.Info("Uploading %s SBOM to s3://%s/%s", sbomFormat, bucket, key)
    
    file, err := os.Open(localFile)
    if err != nil {
        return fmt.Errorf("failed to open file: %w", err)
    }
    defer file.Close()
    
    contentType := "application/json"
    
    _, err = s.client.PutObject(ctx, &s3.PutObjectInput{
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

func (s *S3Client) Download(ctx context.Context, bucket, key, localFile string) error {
    logger.Debug("Downloading s3://%s/%s to %s", bucket, key, localFile)
    
    result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String(bucket),
        Key:    aws.String(key),
    })
    if err != nil {
        return fmt.Errorf("failed to download from S3: %w", err)
    }
    defer result.Body.Close()
    
    file, err := os.Create(localFile)
    if err != nil {
        return fmt.Errorf("failed to create local file: %w", err)
    }
    defer file.Close()
    
    _, err = io.Copy(file, result.Body)
    if err != nil {
        return fmt.Errorf("failed to write file: %w", err)
    }
    
    return nil
}

func (s *S3Client) ListObjects(ctx context.Context, bucket, prefix string) ([]string, error) {
    logger.Debug("Listing objects in s3://%s with prefix: %s", bucket, prefix)
    
    var keys []string
    
    paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
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
