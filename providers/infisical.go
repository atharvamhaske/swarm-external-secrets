package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
	infisical "github.com/infisical/go-sdk"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

const (
	defaultInfisicalSiteURL  = "https://app.infisical.com"
	defaultInfisicalEnv      = "dev"
	defaultInfisicalPath     = "/"
	infisicalRetrieveTimeout = 30 * time.Second
	infisicalMaxAttempts     = 3
	infisicalRetryBase       = 200 * time.Millisecond
	maxInfisicalBodyBytes    = 10 << 20 // 10 MiB
)

// infisicalHTTPClient bounds every secret read. The request context cancels
// the connection when the caller times out; Client.Timeout is the hard cap
// when the caller does not set one.
var infisicalHTTPClient = &http.Client{Timeout: infisicalRetrieveTimeout}

// InfisicalProvider implements SecretsProvider for Infisical.
type InfisicalProvider struct {
	config *InfisicalConfig
	client infisical.InfisicalClientInterface
	cancel context.CancelFunc
}

// InfisicalConfig holds Infisical API client settings.
type InfisicalConfig struct {
	ClientID     string
	ClientSecret string
	Token        string // pre-issued bearer; skips Universal Auth when set
	ProjectID    string
	Environment  string
	SecretPath   string
	SiteURL      string
}

// Initialize sets up the Infisical provider.
func (p *InfisicalProvider) Initialize(config map[string]string) error {
	token := utils.GetConfigOrDefault(config, "INFISICAL_TOKEN", "")
	clientID := utils.GetConfigOrDefault(config, "INFISICAL_CLIENT_ID", "")
	clientSecret := utils.GetConfigOrDefault(config, "INFISICAL_CLIENT_SECRET", "")
	if token == "" && (clientID == "" || clientSecret == "") {
		return fmt.Errorf("INFISICAL_TOKEN or both INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET are required")
	}

	projectID := utils.GetConfigOrDefault(config, "INFISICAL_PROJECT_ID", "")
	if projectID == "" {
		return fmt.Errorf("INFISICAL_PROJECT_ID is required")
	}

	siteURL, err := validateInfisicalSiteURL(utils.GetConfigOrDefault(config, "INFISICAL_SITE_URL", defaultInfisicalSiteURL))
	if err != nil {
		return err
	}

	p.config = &InfisicalConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Token:        token,
		ProjectID:    projectID,
		Environment:  utils.GetConfigOrDefault(config, "INFISICAL_ENVIRONMENT", defaultInfisicalEnv),
		SecretPath:   normalizeInfisicalSecretPath(utils.GetConfigOrDefault(config, "INFISICAL_SECRET_PATH", defaultInfisicalPath)),
		SiteURL:      siteURL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	client := infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          siteURL,
		AutoTokenRefresh: infisical.BoolPtr(token == ""),
		SilentMode:       true,
	})

	if token != "" {
		client.Auth().SetAccessToken(token)
	} else if _, err := client.Auth().UniversalAuthLogin(clientID, clientSecret); err != nil {
		cancel()
		return fmt.Errorf("infisical universal auth: %w", err)
	}

	p.client = client
	p.cancel = cancel

	log.Infof("Successfully initialized Infisical provider (site: %s, project: %s, env: %s)",
		p.config.SiteURL, p.config.ProjectID, p.config.Environment)
	return nil
}

// GetSecret retrieves a secret value from Infisical.
func (p *InfisicalProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, infisicalRetrieveTimeout)
		defer cancel()
	}

	secretName := p.resolveSecretName(secretInfo)
	projectID, environment, secretPath := p.parseSecretPath(secretInfo.SecretPath)

	log.Debugf("Reading secret from Infisical: %s (project=%s, env=%s, path=%s)",
		secretName, projectID, environment, secretPath)

	// The pinned SDK Retrieve call does not take a context and its HTTP client
	// has no timeout, so a hung connection would outlive this call. Read with
	// net/http so cancellation closes the request.
	secretValue, err := p.retrieveSecret(ctx, projectID, environment, secretPath, secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Infisical secret: %w", err)
	}

	extracted, err := ExtractSecretValue(secretValue, secretInfo.SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %w", err)
	}
	return extracted, nil
}

// SupportsRotation indicates Infisical supports rotation monitoring.
func (p *InfisicalProvider) SupportsRotation() bool { return true }

// GetSecretFieldLabel returns the label key used for JSON field extraction.
func (p *InfisicalProvider) GetSecretFieldLabel() string { return "infisical_field" }

// BuildSecretPath encodes project/env/folder/name for tracking.
// Format: {projectID}/{environment}[/{folders...}]/{secretName}
func (p *InfisicalProvider) BuildSecretPath(req secrets.Request) string {
	secretName := p.resolveSecretNameFromRequest(req)
	projectID, environment, secretPath := p.resolveContextFromRequest(req)
	if secretPath == "/" {
		return fmt.Sprintf("%s/%s/%s", projectID, environment, secretName)
	}
	return fmt.Sprintf("%s/%s%s/%s", projectID, environment, secretPath, secretName)
}

// GetProviderName returns "infisical".
func (p *InfisicalProvider) GetProviderName() string { return "infisical" }

// Close stops the SDK token-refresh loop.
func (p *InfisicalProvider) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

func (p *InfisicalProvider) resolveSecretNameFromRequest(req secrets.Request) string {
	if name := req.SecretLabels["infisical_secret_name"]; name != "" {
		return name
	}
	return strings.ToUpper(req.SecretName)
}

func (p *InfisicalProvider) resolveSecretName(secretInfo *SecretInfo) string {
	if name := secretInfo.Labels["infisical_secret_name"]; name != "" {
		return name
	}
	return strings.ToUpper(secretInfo.DockerSecretName)
}

func (p *InfisicalProvider) resolveContextFromRequest(req secrets.Request) (projectID, environment, secretPath string) {
	projectID, environment, secretPath = p.config.ProjectID, p.config.Environment, p.config.SecretPath
	if v := req.SecretLabels["infisical_project_id"]; v != "" {
		projectID = v
	}
	if v := req.SecretLabels["infisical_environment"]; v != "" {
		environment = v
	}
	if v := req.SecretLabels["infisical_secret_path"]; v != "" {
		secretPath = normalizeInfisicalSecretPath(v)
	}
	return projectID, environment, secretPath
}

func (p *InfisicalProvider) parseSecretPath(secretPath string) (projectID, environment, path string) {
	parts := strings.Split(secretPath, "/")
	if len(parts) < 3 {
		return p.config.ProjectID, p.config.Environment, p.config.SecretPath
	}
	projectID, environment = parts[0], parts[1]
	if len(parts) == 3 {
		return projectID, environment, "/"
	}
	return projectID, environment, "/" + strings.Join(parts[2:len(parts)-1], "/")
}

func normalizeInfisicalSecretPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	return path
}

func (p *InfisicalProvider) retrieveSecret(ctx context.Context, projectID, environment, secretPath, secretName string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < infisicalMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		value, retryAfter, retry, err := p.retrieveSecretOnce(ctx, projectID, environment, secretPath, secretName)
		if err == nil {
			return value, nil
		}
		lastErr = err
		if !retry || attempt == infisicalMaxAttempts-1 {
			return "", err
		}
		delay := infisicalJitter(attempt)
		if retryAfter != nil {
			delay = *retryAfter
		}
		if err := sleepInfisical(ctx, delay); err != nil {
			return "", err
		}
	}
	return "", lastErr
}

func (p *InfisicalProvider) retrieveSecretOnce(ctx context.Context, projectID, environment, secretPath, secretName string) (string, *time.Duration, bool, error) {
	token := p.client.Auth().GetAccessToken()
	if token == "" {
		return "", nil, false, fmt.Errorf("infisical client is not authenticated")
	}
	endpoint, err := infisicalRawSecretURL(p.config.SiteURL, secretName, projectID, environment, secretPath)
	if err != nil {
		return "", nil, false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, false, fmt.Errorf("failed to create Infisical request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	// Site URL is restricted to https at Initialize. Tests point this client at a local server.
	resp, err := infisicalHTTPClient.Do(req) // #nosec G704
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", nil, false, err
		}
		return "", nil, true, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInfisicalBodyBytes))
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", nil, false, err
		}
		return "", nil, true, fmt.Errorf("failed to read Infisical response: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		var payload struct {
			Secret struct {
				SecretValue string `json:"secretValue"`
			} `json:"secret"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "", nil, false, fmt.Errorf("failed to parse Infisical response: %w", err)
		}
		return payload.Secret.SecretValue, nil, false, nil
	}

	retry := infisicalRetryableStatus(resp.StatusCode)
	if !retry {
		return "", nil, false, infisicalStatusError(resp.StatusCode, body)
	}
	retryAfter, ok := parseInfisicalRetryAfter(resp.Header.Get("Retry-After"))
	if !ok {
		return "", nil, true, infisicalStatusError(resp.StatusCode, body)
	}
	return "", &retryAfter, true, infisicalStatusError(resp.StatusCode, body)
}

func infisicalRawSecretURL(siteURL, secretName, projectID, environment, secretPath string) (string, error) {
	base := strings.TrimSuffix(strings.TrimRight(siteURL, "/"), "/api")
	endpoint, err := url.JoinPath(base, "api", "v3", "secrets", "raw", secretName)
	if err != nil {
		return "", fmt.Errorf("invalid Infisical secret URL: %w", err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid Infisical secret URL: %w", err)
	}
	query := parsed.Query()
	query.Set("workspaceId", projectID)
	query.Set("environment", environment)
	query.Set("secretPath", secretPath)
	query.Set("expandSecretReferences", "true")
	query.Set("include_imports", "false")
	query.Set("type", "shared")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func infisicalRetryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func infisicalStatusError(status int, body []byte) error {
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Message != "" {
		return fmt.Errorf("infisical api status %d: %s", status, payload.Message)
	}
	return fmt.Errorf("infisical api status %d", status)
}

func parseInfisicalRetryAfter(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func infisicalJitter(attempt int) time.Duration {
	shift := attempt
	if shift > 3 {
		shift = 3
	}
	ceiling := infisicalRetryBase << shift
	return time.Duration(rand.Int64N(int64(ceiling) + 1))
}

func sleepInfisical(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validateInfisicalSiteURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", fmt.Errorf("INFISICAL_SITE_URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid INFISICAL_SITE_URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("INFISICAL_SITE_URL must use https scheme")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("INFISICAL_SITE_URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("INFISICAL_SITE_URL must not include userinfo")
	}
	return parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.EscapedPath(), "/"), nil
}
