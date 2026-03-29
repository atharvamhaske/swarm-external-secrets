package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/vault-swarm-plugin/internal/spiffejwt"
)

func main() {
	var (
		once        = flag.Bool("once", false, "Fetch one JWT-SVID and exit")
		outputPath  = flag.String("output", getEnvOrDefault("AWS_WEB_IDENTITY_TOKEN_FILE", ""), "Output path for the JWT token file")
		audience    = flag.String("audience", getEnvOrDefault("AWS_SPIFFE_JWT_AUDIENCE", ""), "Audience to request from SPIRE")
		socketAddr  = flag.String("socket", getEnvOrDefault("SPIFFE_ENDPOINT_SOCKET", ""), "SPIFFE Workload API socket URI")
		minRefresh  = flag.Duration("min-refresh", parseDurationOrDefault(getEnvOrDefault("SPIFFE_JWT_MIN_REFRESH", "30s")), "Minimum refresh interval")
		refreshSkew = flag.Duration("refresh-skew", parseDurationOrDefault(getEnvOrDefault("SPIFFE_JWT_REFRESH_SKEW", "2m")), "How early to refresh before JWT expiry")
	)
	flag.Parse()

	if *outputPath == "" {
		log.Fatal("AWS_WEB_IDENTITY_TOKEN_FILE or -output is required")
	}

	cfg := spiffejwt.Config{
		Audience:       *audience,
		EndpointSocket: *socketAddr,
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		expiry, err := fetchAndWriteToken(ctx, cfg, *outputPath)
		if err != nil {
			log.Fatalf("failed to fetch/write JWT-SVID: %v", err)
		}

		if *once {
			return
		}

		wait := time.Until(expiry.Add(-*refreshSkew))
		if wait < *minRefresh {
			wait = *minRefresh
		}

		log.Printf("next token refresh in %s", wait.Round(time.Second))

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func fetchAndWriteToken(ctx context.Context, cfg spiffejwt.Config, outputPath string) (time.Time, error) {
	token, expiry, err := cfg.FetchToken(ctx)
	if err != nil {
		return time.Time{}, err
	}

	if err := writeFileAtomically(outputPath, []byte(token), 0o600); err != nil {
		return time.Time{}, err
	}

	log.Printf("wrote JWT-SVID to %s (expires at %s)", outputPath, expiry.UTC().Format(time.RFC3339))
	return expiry, nil
}

func writeFileAtomically(path string, contents []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".jwt-*")
	if err != nil {
		return fmt.Errorf("failed to create temp token file: %w", err)
	}

	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write temp token file: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to chmod temp token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp token file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to move temp token file into place: %w", err)
	}

	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseDurationOrDefault(durationStr string) time.Duration {
	if duration, err := time.ParseDuration(durationStr); err == nil {
		return duration
	}
	return 30 * time.Second
}
