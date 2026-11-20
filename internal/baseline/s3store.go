package baseline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bellu/bskg/internal/httpx"
)

// S3Store reads baseline objects from S3.
type S3Store struct {
	client *s3.Client
}

// NewS3Store uses the default AWS credential chain (including the instance
// role). When no credentials are found it falls back to anonymous access.
// Credential values are never logged or returned in errors.
func NewS3Store(ctx context.Context, region string) (*S3Store, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("baseline: load AWS config: %w", err)
	}
	if cfg.Credentials == nil {
		cfg.Credentials = aws.AnonymousCredentials{}
	} else if _, cerr := cfg.Credentials.Retrieve(ctx); cerr != nil {
		cfg.Credentials = aws.AnonymousCredentials{}
	}
	return &S3Store{client: s3.NewFromConfig(cfg)}, nil
}

// Get opens an object. Network failures, 429 and 5xx responses are retryable.
func (s *S3Store) Get(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		var re *awshttp.ResponseError
		if errors.As(err, &re) {
			c := re.HTTPStatusCode()
			if c == http.StatusTooManyRequests || c >= 500 {
				return nil, httpx.Retryable(err)
			}
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, httpx.Retryable(err)
	}
	return out.Body, nil
}
