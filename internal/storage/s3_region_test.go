package storage

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// newTestS3Client builds an S3Client without touching the SDK default chain.
func newTestS3Client(defaultRegion string, customEndpoint bool) *S3Client {
	cfg := aws.Config{Region: defaultRegion}
	return &S3Client{
		awsCfg:         cfg,
		defaultClient:  s3.NewFromConfig(cfg),
		customEndpoint: customEndpoint,
		regionClients:  map[string]*s3.Client{},
		bucketRegions:  map[string]string{},
	}
}

// stubBucketRegion replaces the package resolver for the duration of the test
// and returns a pointer to a call counter.
func stubBucketRegion(t *testing.T, fn func(bucket string) (string, error)) *int {
	t.Helper()
	calls := 0
	orig := bucketRegionResolver
	bucketRegionResolver = func(_ context.Context, _ *s3.Client, bucket string) (string, error) {
		calls++
		return fn(bucket)
	}
	t.Cleanup(func() { bucketRegionResolver = orig })
	return &calls
}

func TestClientFor_SameRegionUsesDefaultClient(t *testing.T) {
	calls := stubBucketRegion(t, func(string) (string, error) { return "us-east-1", nil })
	c := newTestS3Client("us-east-1", false)

	got := c.clientFor(context.Background(), "bucket-a")
	if got != c.defaultClient {
		t.Fatal("expected the default client when bucket region matches default region")
	}
	if *calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", *calls)
	}
}

func TestClientFor_DifferentRegionCreatesRegionalClientOnce(t *testing.T) {
	calls := stubBucketRegion(t, func(string) (string, error) { return "eu-central-1", nil })
	c := newTestS3Client("us-east-1", false)
	ctx := context.Background()

	first := c.clientFor(ctx, "bucket-eu")
	if first == c.defaultClient {
		t.Fatal("expected a region-specific client, got the default client")
	}
	if got := first.Options().Region; got != "eu-central-1" {
		t.Fatalf("regional client region = %q, want eu-central-1", got)
	}

	second := c.clientFor(ctx, "bucket-eu")
	if second != first {
		t.Fatal("expected the cached regional client on the second call")
	}
	if *calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (region must be cached per bucket)", *calls)
	}
}

func TestClientFor_TwoBucketsInSameForeignRegionShareClient(t *testing.T) {
	stubBucketRegion(t, func(string) (string, error) { return "ap-southeast-2", nil })
	c := newTestS3Client("us-east-1", false)
	ctx := context.Background()

	a := c.clientFor(ctx, "bucket-a")
	b := c.clientFor(ctx, "bucket-b")
	if a != b {
		t.Fatal("expected buckets in the same region to share one regional client")
	}
	if len(c.regionClients) != 1 {
		t.Fatalf("regionClients size = %d, want 1", len(c.regionClients))
	}
}

func TestClientFor_ResolverErrorFallsBackToDefaultAndCaches(t *testing.T) {
	calls := stubBucketRegion(t, func(string) (string, error) { return "", errors.New("AccessDenied") })
	c := newTestS3Client("us-east-1", false)
	ctx := context.Background()

	if got := c.clientFor(ctx, "bucket-x"); got != c.defaultClient {
		t.Fatal("expected fallback to default client on resolver error")
	}
	if got := c.clientFor(ctx, "bucket-x"); got != c.defaultClient {
		t.Fatal("expected fallback to default client on second call")
	}
	if *calls != 1 {
		t.Fatalf("resolver calls = %d, want 1 (failures must be cached, not retried per request)", *calls)
	}
}

func TestClientFor_EmptyResolvedRegionUsesDefault(t *testing.T) {
	stubBucketRegion(t, func(string) (string, error) { return "", nil })
	c := newTestS3Client("us-east-1", false)

	if got := c.clientFor(context.Background(), "bucket-x"); got != c.defaultClient {
		t.Fatal("expected default client when resolver returns an empty region")
	}
}

func TestClientFor_CustomEndpointSkipsRegionResolution(t *testing.T) {
	calls := stubBucketRegion(t, func(string) (string, error) {
		t.Fatal("resolver must not be called for custom endpoints")
		return "", nil
	})
	c := newTestS3Client("us-east-1", true)

	if got := c.clientFor(context.Background(), "bucket-x"); got != c.defaultClient {
		t.Fatal("expected default client for custom endpoint")
	}
	if *calls != 0 {
		t.Fatalf("resolver calls = %d, want 0", *calls)
	}
}

func TestNewS3Client_CustomEndpointUsesPathStyle(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "http://localhost:9000")
	t.Setenv("AWS_ENDPOINT_URL_S3", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")

	c, err := NewS3Client(context.Background())
	if err != nil {
		t.Fatalf("NewS3Client: %v", err)
	}
	if !c.customEndpoint {
		t.Fatal("expected customEndpoint=true when AWS_ENDPOINT_URL is set")
	}
	if !c.defaultClient.Options().UsePathStyle {
		t.Fatal("expected path-style addressing for a custom endpoint")
	}
}

func TestNewS3Client_AWSEndpointUsesVirtualHostedStyle(t *testing.T) {
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_ENDPOINT_URL_S3", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")

	c, err := NewS3Client(context.Background())
	if err != nil {
		t.Fatalf("NewS3Client: %v", err)
	}
	if c.customEndpoint {
		t.Fatal("expected customEndpoint=false without AWS_ENDPOINT_URL")
	}
	if c.defaultClient.Options().UsePathStyle {
		t.Fatal("expected virtual-hosted-style addressing against real AWS")
	}
	if got := c.awsCfg.Region; got != "us-east-1" {
		t.Fatalf("default region = %q, want us-east-1", got)
	}
}

// fakeS3 returns an S3 client pointed at an httptest server whose HEAD
// handler is supplied by the caller.
func fakeS3(t *testing.T, handler http.HandlerFunc) *s3.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return s3.New(s3.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(srv.URL),
		UsePathStyle: true,
		Credentials:  aws.AnonymousCredentials{},
		Retryer:      aws.NopRetryer{},
	})
}

func TestResolveBucketRegion_FromSuccessfulHeadBucket(t *testing.T) {
	client := fakeS3(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method = %s, want HEAD", r.Method)
		}
		w.Header().Set(bucketRegionHeader, "us-west-2")
		w.WriteHeader(http.StatusOK)
	})

	got, err := resolveBucketRegion(context.Background(), client, "bucket-a")
	if err != nil {
		t.Fatalf("resolveBucketRegion: %v", err)
	}
	if got != "us-west-2" {
		t.Errorf("region = %q, want us-west-2", got)
	}
}

func TestResolveBucketRegion_FromPermanentRedirect(t *testing.T) {
	client := fakeS3(t, func(w http.ResponseWriter, _ *http.Request) {
		// What S3 sends when the request hits the wrong regional endpoint.
		w.Header().Set(bucketRegionHeader, "eu-central-1")
		w.WriteHeader(http.StatusMovedPermanently)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>PermanentRedirect</Code><Message>The bucket you are attempting to access must be addressed using the specified endpoint.</Message></Error>`))
	})

	got, err := resolveBucketRegion(context.Background(), client, "bucket-eu")
	if err != nil {
		t.Fatalf("resolveBucketRegion should recover the region from a 301, got error: %v", err)
	}
	if got != "eu-central-1" {
		t.Errorf("region = %q, want eu-central-1", got)
	}
}

func TestResolveBucketRegion_FromForbidden(t *testing.T) {
	client := fakeS3(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(bucketRegionHeader, "ap-southeast-2")
		w.WriteHeader(http.StatusForbidden)
	})

	got, err := resolveBucketRegion(context.Background(), client, "bucket-x")
	if err != nil {
		t.Fatalf("resolveBucketRegion should recover the region from a 403, got error: %v", err)
	}
	if got != "ap-southeast-2" {
		t.Errorf("region = %q, want ap-southeast-2", got)
	}
}

func TestResolveBucketRegion_NoHeaderIsAnError(t *testing.T) {
	client := fakeS3(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	got, err := resolveBucketRegion(context.Background(), client, "missing-bucket")
	if err == nil {
		t.Fatalf("expected an error when no region header is present, got region %q", got)
	}
}
