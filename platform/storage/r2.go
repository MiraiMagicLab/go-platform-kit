package storage

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type r2Store struct {
	client     *s3.Client
	presigner  *s3.PresignClient
	bucket     string
	publicBase string
}

func openR2(ctx context.Context, cfg Config) (ObjectStore, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.AccountID)
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion("auto"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")),
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("storage: load R2 config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	return &r2Store{
		client:     client,
		presigner:  s3.NewPresignClient(client),
		bucket:     cfg.Bucket,
		publicBase: strings.TrimRight(cfg.PublicBase, "/"),
	}, nil
}

func (s *r2Store) Put(ctx context.Context, key string, body io.Reader, opts PutOptions) error {
	safe, err := normalizeKey(key)
	if err != nil {
		return err
	}
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(safe),
		Body:   body,
	}
	if opts.ContentType != "" {
		input.ContentType = aws.String(opts.ContentType)
	}
	_, err = s.client.PutObject(ctx, input)
	return err
}

func (s *r2Store) Delete(ctx context.Context, key string) error {
	safe, err := normalizeKey(key)
	if err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(safe),
	})
	return err
}

func (s *r2Store) URL(key string) string {
	safe, err := normalizeKey(key)
	if err != nil {
		return ""
	}
	if s.publicBase != "" {
		return s.publicBase + "/" + safe
	}
	return fmt.Sprintf("r2://%s/%s", s.bucket, safe)
}

func (s *r2Store) SignedURL(ctx context.Context, key string, expiry time.Duration) (string, error) {
	if expiry <= 0 {
		expiry = 15 * time.Minute
	}
	safe, err := normalizeKey(key)
	if err != nil {
		return "", err
	}
	out, err := s.presigner.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(safe),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", err
	}
	return out.URL, nil
}
