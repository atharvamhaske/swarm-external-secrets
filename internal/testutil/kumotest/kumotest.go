// Package kumotest provides helpers for integration tests against a Kumo AWS emulator.
package kumotest

import (
	"context"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	defaultEndpoint = "http://127.0.0.1:4566"
	defaultRegion   = "us-east-1"
	defaultAccess   = "test"
	defaultSecret   = "test"
)

// Endpoint returns the AWS API endpoint for Kumo (Secrets Manager and shared services).
func Endpoint() string {
	if v := os.Getenv("AWS_ENDPOINT_URL"); v != "" {
		return v
	}
	return defaultEndpoint
}

// KMSEndpoint returns the AWS KMS endpoint override for Kumo.
func KMSEndpoint() string {
	if v := os.Getenv("AWS_KMS_ENDPOINT"); v != "" {
		return v
	}
	return Endpoint()
}

// Region returns the AWS region used in Kumo tests.
func Region() string {
	if v := os.Getenv("AWS_REGION"); v != "" {
		return v
	}
	return defaultRegion
}

// ProviderSettings returns plugin-style settings for AWS provider and KMS transformer tests.
func ProviderSettings() map[string]string {
	return map[string]string{
		"AWS_REGION":            Region(),
		"AWS_ACCESS_KEY_ID":     accessKey(),
		"AWS_SECRET_ACCESS_KEY": secretKey(),
		"AWS_ENDPOINT_URL":      Endpoint(),
		"AWS_KMS_ENDPOINT":      KMSEndpoint(),
	}
}

// Require skips the test when Kumo is not reachable.
func Require(t *testing.T) {
	t.Helper()

	if os.Getenv("KUMO_SKIP") == "1" {
		t.Skip("KUMO_SKIP=1")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if !Available(ctx) {
		t.Skipf("Kumo not available at %s — start with: docker run -d -p 4566:4566 ghcr.io/sivchari/kumo:latest", Endpoint())
	}
}

// Available reports whether Kumo accepts connections on the configured endpoint.
func Available(ctx context.Context) bool {
	host, err := endpointHost(Endpoint())
	if err != nil {
		return false
	}

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// AWSConfig loads SDK config for Kumo with static test credentials.
func AWSConfig(ctx context.Context) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithRegion(Region()),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKey(),
			secretKey(),
			"",
		)),
	)
}

// SecretsManagerClient returns a Secrets Manager client pointed at Kumo.
func SecretsManagerClient(ctx context.Context) (*secretsmanager.Client, error) {
	cfg, err := AWSConfig(ctx)
	if err != nil {
		return nil, err
	}

	return secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		o.BaseEndpoint = aws.String(Endpoint())
	}), nil
}

// KMSClient returns a KMS client pointed at Kumo.
func KMSClient(ctx context.Context) (*kms.Client, error) {
	cfg, err := AWSConfig(ctx)
	if err != nil {
		return nil, err
	}

	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(KMSEndpoint())
	}), nil
}

func accessKey() string {
	if v := os.Getenv("AWS_ACCESS_KEY_ID"); v != "" {
		return v
	}
	return defaultAccess
}

func secretKey() string {
	if v := os.Getenv("AWS_SECRET_ACCESS_KEY"); v != "" {
		return v
	}
	return defaultSecret
}

func endpointHost(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	host := u.Host
	if host == "" {
		host = u.Path
	}
	if host == "" {
		return "127.0.0.1:4566", nil
	}

	if _, _, err := net.SplitHostPort(host); err != nil {
		switch u.Scheme {
		case "https":
			host = net.JoinHostPort(host, "443")
		default:
			host = net.JoinHostPort(host, "4566")
		}
	}

	return host, nil
}
