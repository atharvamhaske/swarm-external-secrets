package providers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/dilutedev/doppler"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// It uses the community Go client: https://github.com/dilutedev/doppler
// Official API reference: https://docs.doppler.com/
type DopplerProvider struct {
	client *doppler.Doppler
	config *DopplerConfig
}

// DopplerConfig holds default project and config (environment) when not overridden per secret.
type DopplerConfig struct {
	DefaultProject string
	DefaultConfig  string
}

// Initialize validates the API token and stores defaults.
// Token: DOPPLER_KEY (preferred by the SDK) or DOPPLER_TOKEN as an alias.
func (d *DopplerProvider) Initialize(config map[string]string) error {
	key := getConfigOrDefault(config, "DOPPLER_KEY", "")
	if key == "" {
		key = config["DOPPLER_TOKEN"]
	}
	if key == "" {
		return fmt.Errorf("DOPPLER_KEY or DOPPLER_TOKEN is required for Doppler authentication")
	}

	client, err := doppler.New(key)
	if err != nil {
		return fmt.Errorf("failed to create Doppler client: %w", err)
	}

	d.client = client
	d.config = &DopplerConfig{
		DefaultProject: getConfigOrDefault(config, "DOPPLER_PROJECT", ""),
		DefaultConfig:  getConfigOrDefault(config, "DOPPLER_CONFIG", ""),
	}

	log.Printf("Successfully initialized Doppler provider (default project=%q config=%q)", d.config.DefaultProject, d.config.DefaultConfig)
	return nil
}

// dopplerLabel returns a trimmed label value, or fallback when the label is missing or blank.
func dopplerLabel(labels map[string]string, key, fallback string) string {
	if v := strings.TrimSpace(labels[key]); v != "" {
		return v
	}
	return fallback
}

func (d *DopplerProvider) resolveRef(req secrets.Request) (project, config, name string, err error) {
	project = dopplerLabel(req.SecretLabels, "doppler_project", d.config.DefaultProject)
	config = dopplerLabel(req.SecretLabels, "doppler_config", d.config.DefaultConfig)
	name = dopplerLabel(req.SecretLabels, "doppler_secret", strings.TrimSpace(req.SecretName))

	switch {
	case project == "" || config == "":
		return "", "", "", fmt.Errorf(
			"doppler project and config are required (set DOPPLER_PROJECT and DOPPLER_CONFIG or labels doppler_project and doppler_config)")
	case name == "":
		return "", "", "", fmt.Errorf(
			"doppler secret name is required (label doppler_secret or Swarm secret name)")
	default:
		return project, config, name, nil
	}
}

func dopplerSecretValue(s *doppler.Secret) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("empty Doppler secret response")
	}
	val := s.Value.Computed
	if val == "" {
		val = s.Value.Raw
	}
	if val == "" {
		return nil, fmt.Errorf("doppler secret %s has empty value", s.Name)
	}
	return []byte(val), nil
}

// GetSecret fetches a single secret by project, config, and secret name.
func (d *DopplerProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	_ = ctx
	project, cfg, name, err := d.resolveRef(req)
	if err != nil {
		return nil, err
	}
	log.Printf("Reading secret from Doppler: project=%s config=%s name=%s", project, cfg, name)

	s, err := d.client.RetrieveSecret(project, cfg, name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Doppler secret: %w", err)
	}
	return dopplerSecretValue(s)
}

// SupportsRotation indicates Doppler supports polling the same secret and comparing hashes.
func (d *DopplerProvider) SupportsRotation() bool {
	return true
}

// CheckSecretChanged re-reads the secret referenced by SecretPath (project|config|name).
func (d *DopplerProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	_ = ctx
	project, cfg, name, err := ParseDopplerSecretPath(secretInfo.SecretPath)
	if err != nil {
		return false, err
	}
	s, err := d.client.RetrieveSecret(project, cfg, name)
	if err != nil {
		return false, fmt.Errorf("error reading Doppler secret for rotation check: %w", err)
	}
	current, err := dopplerSecretValue(s)
	if err != nil {
		return false, err
	}
	currentHash := fmt.Sprintf("%x", sha256.Sum256(current))
	return currentHash != secretInfo.LastHash, nil
}

// ParseDopplerSecretPath parses the tracker path produced by buildDopplerSecretPath (project|config|secretName).
// It is used by CheckSecretChanged and by the driver when rebuilding labels for rotation.
func ParseDopplerSecretPath(path string) (project, config, name string, err error) {
	parts := strings.SplitN(path, "|", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("invalid Doppler secret path (expected project|config|name): %q", path)
	}
	return parts[0], parts[1], parts[2], nil
}

// GetProviderName returns the provider identifier used in driver rotation wiring.
func (d *DopplerProvider) GetProviderName() string {
	return "doppler"
}

// Close releases resources; HTTP client needs no explicit close.
func (d *DopplerProvider) Close() error {
	return nil
}
