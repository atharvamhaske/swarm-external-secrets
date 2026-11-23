package providers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type identityTokenFetcherFunc func(context.Context) ([]byte, error)

func (f identityTokenFetcherFunc) FetchIdentityToken(ctx context.Context) ([]byte, error) {
	return f(ctx)
}

type webIdentityRoleAssumerFunc func(context.Context) (*sts.AssumeRoleWithWebIdentityOutput, error)

func (f webIdentityRoleAssumerFunc) AssumeRoleWithWebIdentity(
	ctx context.Context, _ *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options),
) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return f(ctx)
}

func TestSPIFFECredentialsCacheRefreshTimeoutAndRetry(t *testing.T) {
	for _, stalledStage := range []string{"JWT", "STS"} {
		t.Run(stalledStage, func(t *testing.T) {
			t.Parallel()

			var fetches atomic.Int32
			var exchanges atomic.Int32
			canceled := make(chan struct{})
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			waitForTimeout := func(ctx context.Context) error {
				select {
				case <-ctx.Done():
					close(canceled)
					return ctx.Err()
				case <-release:
					return errors.New("test finished before refresh was canceled")
				}
			}
			var tokenDeadline time.Time
			provider := &spiffeCredentialsProvider{
				refreshTimeout: 50 * time.Millisecond,
				tokenSource: identityTokenFetcherFunc(func(ctx context.Context) ([]byte, error) {
					attempt := fetches.Add(1)
					tokenDeadline, _ = ctx.Deadline()
					if stalledStage == "JWT" && attempt == 1 {
						return nil, waitForTimeout(ctx)
					}
					return []byte("test-jwt-svid"), nil
				}),
				client: webIdentityRoleAssumerFunc(func(ctx context.Context) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					attempt := exchanges.Add(1)
					if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(tokenDeadline) {
						t.Error("JWT retrieval and STS exchange must share one refresh deadline")
					}
					if stalledStage == "STS" && attempt == 1 {
						return nil, waitForTimeout(ctx)
					}
					return &sts.AssumeRoleWithWebIdentityOutput{Credentials: &types.Credentials{
						AccessKeyId:     aws.String("test-access-key"),
						SecretAccessKey: aws.String("test-secret-key"),
						SessionToken:    aws.String("test-session-token"),
						Expiration:      aws.Time(time.Now().Add(time.Hour)),
					}}, nil
				}),
			}
			cache := aws.NewCredentialsCache(provider)
			// This outer timeout prevents a broken refresh from hanging the test.
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if _, err := cache.Retrieve(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("first Retrieve() error = %v, want deadline exceeded", err)
			}
			select {
			case <-canceled:
			default:
				t.Fatal("credentials cache returned without canceling the stalled refresh")
			}

			for range 2 {
				creds, err := cache.Retrieve(ctx)
				if err != nil {
					t.Fatalf("Retrieve() after timeout error = %v", err)
				}
				if creds.AccessKeyID != "test-access-key" || creds.Source != spiffeCredentialSource {
					t.Fatal("Retrieve() did not return the refreshed SPIFFE credentials")
				}
			}
			if got := fetches.Load(); got != 2 {
				t.Errorf("JWT fetches = %d, want 2 (retry followed by cache reuse)", got)
			}
			wantExchanges := int32(1)
			if stalledStage == "STS" {
				wantExchanges = 2
			}
			if got := exchanges.Load(); got != wantExchanges {
				t.Errorf("STS exchanges = %d, want %d", got, wantExchanges)
			}
		})
	}
}

func TestSPIFFECredentialsProviderDefaultRefreshTimeout(t *testing.T) {
	provider := &spiffeCredentialsProvider{
		tokenSource: identityTokenFetcherFunc(func(ctx context.Context) ([]byte, error) {
			deadline, ok := ctx.Deadline()
			if remaining := time.Until(deadline); !ok || remaining <= 29*time.Second || remaining > 30*time.Second {
				t.Errorf("refresh timeout = %v, want 30 seconds", remaining)
			}
			return nil, errors.New("stop after checking the deadline")
		}),
	}
	_, _ = provider.Retrieve(context.Background())
}
