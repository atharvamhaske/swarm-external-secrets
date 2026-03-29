package spiffejwt

import (
	"context"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Config holds SPIFFE Workload API settings for JWT-SVID retrieval.
type Config struct {
	Audience       string
	EndpointSocket string
}

// Validate ensures the minimum parameters are present.
func (c Config) Validate() error {
	if c.Audience == "" {
		return fmt.Errorf("AWS_SPIFFE_JWT_AUDIENCE is required for SPIFFE web identity auth")
	}
	return nil
}

// FetchToken fetches a fresh JWT-SVID and returns the serialized token plus expiry.
func (c Config) FetchToken(ctx context.Context) (string, time.Time, error) {
	if err := c.Validate(); err != nil {
		return "", time.Time{}, err
	}

	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: c.Audience,
	}, c.workloadAPIOptions()...)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to fetch JWT-SVID from SPIRE Workload API: %w", err)
	}

	return svid.Marshal(), svid.Expiry, nil
}

func (c Config) workloadAPIOptions() []workloadapi.ClientOption {
	if c.EndpointSocket == "" {
		return nil
	}

	return []workloadapi.ClientOption{workloadapi.WithAddr(c.EndpointSocket)}
}
