package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/docker/docker/api/types/swarm"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"

	"github.com/sciops-org/swarm-external-secrets/internal/secrettransform"
	"github.com/sciops-org/swarm-external-secrets/internal/utils"
	dopplerwebhook "github.com/sciops-org/swarm-external-secrets/internal/webhook/doppler"
	vaultwebhook "github.com/sciops-org/swarm-external-secrets/internal/webhook/vault"
	"github.com/sciops-org/swarm-external-secrets/monitoring"
	"github.com/sciops-org/swarm-external-secrets/providers"
)

// SecretsDriver implements the secrets.Driver interface with multi-provider support
type SecretsDriver struct {
	provider             providers.SecretsProvider
	config               *SecretsConfig
	dockerClient         *dockerclient.Client
	transformer          secrettransform.Transformer      // aws kms service which decrypts ciphertexts
	secretTracker        map[string]*providers.SecretInfo // key: docker secret name
	trackerMutex         sync.RWMutex
	rotationMu           sync.Mutex // serializes rotation cycles (poll loop vs webhook)
	monitorCtx           context.Context
	monitorCancel        context.CancelFunc
	monitor              *monitoring.Monitor
	webInterface         *monitoring.WebInterface
	dopplerWebhookServer *dopplerwebhook.Server
	webhookServer        *vaultwebhook.Server
}

// SecretsConfig holds the configuration for the multi-provider driver
type SecretsConfig struct {
	ProviderType         string
	EnableRotation       bool
	RotationInterval     time.Duration
	EnableMonitoring     bool
	MonitoringPort       int
	WebhookEnable        bool
	DopplerWebhookPort   int
	WebhookPath          string
	DopplerWebhookSecret string
	WebhookAllowUnsigned bool
	Settings             map[string]string
	UseWebhook           bool
	WebhookPort          int
	WebhookSecret        string
}

// NewDriver creates a new Driver instance with multi-provider support
func NewDriver() (*SecretsDriver, error) {
	// Collect all configuration from environment variables
	settings := make(map[string]string)

	// Get provider type (default to vault for backward compatibility)
	providerType := utils.GetEnvOrDefault("SECRETS_PROVIDER", "vault")

	// Collect all environment variables for provider configuration
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			settings[pair[0]] = pair[1]
		}
	}

	config := &SecretsConfig{
		ProviderType:         providerType,
		EnableRotation:       utils.GetEnvOrDefault("ENABLE_ROTATION", "true") == "true",
		RotationInterval:     utils.ParseDurationOrDefault(utils.GetEnvOrDefault("ROTATION_INTERVAL", "10s")),
		EnableMonitoring:     utils.GetEnvOrDefault("ENABLE_MONITORING", "true") == "true",
		MonitoringPort:       utils.ParseIntOrDefault(utils.GetEnvOrDefault("MONITORING_PORT", "8080")),
		WebhookEnable:        utils.GetEnvOrDefault("DOPPLER_WEBHOOK_ENABLE", "false") == "true",
		DopplerWebhookPort:   utils.ParseIntOrDefault(utils.GetEnvOrDefault("DOPPLER_WEBHOOK_PORT", "8081")),
		WebhookPath:          utils.GetEnvOrDefault("DOPPLER_WEBHOOK_PATH", "/webhooks/doppler"),
		DopplerWebhookSecret: utils.GetConfigOrDefault(settings, "DOPPLER_WEBHOOK_SECRET", ""),
		WebhookAllowUnsigned: utils.GetEnvOrDefault("DOPPLER_WEBHOOK_INSECURE", "false") == "true",
		Settings:             settings,
		UseWebhook:           utils.GetEnvOrDefault("USE_WEBHOOK", "false") == "true",
		WebhookPort:          utils.ParseIntOrDefault(utils.GetEnvOrDefault("WEBHOOK_PORT", "9095")),
		WebhookSecret:        os.Getenv("WEBHOOK_SECRET"),
	}

	// Create the appropriate provider
	provider, err := providers.CreateProvider(config.ProviderType)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %v", err)
	}
	config.ProviderType = provider.GetProviderName()

	// Initialize the provider
	if err := provider.Initialize(settings); err != nil {
		log.Errorf("failed to initialize %s provider: %v", config.ProviderType, err)
		return nil, fmt.Errorf("failed to initialize %s provider: %v", config.ProviderType, err)
	}

	// Create Docker client
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		log.Errorf("failed to create docker client: %v", err)
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}

	// Create context for monitoring
	monitorCtx, monitorCancel := context.WithCancel(context.Background())

	var kmsCredentials aws.CredentialsProvider
	if awsProvider, ok := provider.(*providers.AWSProvider); ok {
		kmsCredentials = awsProvider.SPIFFECredentials()
	}

	driver := &SecretsDriver{
		provider:      provider,
		config:        config,
		dockerClient:  dockerClient,
		transformer:   secrettransform.NewAWSKMSTransformer(settings, kmsCredentials),
		secretTracker: make(map[string]*providers.SecretInfo),
		monitorCtx:    monitorCtx,
		monitorCancel: monitorCancel,
	}

	// Initialize monitoring if enabled
	if config.EnableMonitoring {
		driver.monitor = monitoring.NewMonitor(30 * time.Second) // Monitor every 30 seconds
		driver.monitor.SetRotationInterval(config.RotationInterval)
		driver.monitor.Start()

		// Start web interface
		driver.webInterface = monitoring.NewWebInterface(driver.monitor, config.MonitoringPort)
		if err := driver.webInterface.Start(); err != nil {
			log.Warnf("Failed to start web monitoring interface: %v", err)
		}
	}

	// Start webhook or ticker reconciliation if rotation is enabled and the provider supports it.
	if config.EnableRotation && provider.SupportsRotation() && config.UseWebhook && config.ProviderType == "vault" {
		log.Printf("USE_WEBHOOK=true detected for Vault provider; starting webhook server on port %d", config.WebhookPort)
		webhookCfg := &vaultwebhook.Config{
			Port:          config.WebhookPort,
			WebhookSecret: config.WebhookSecret,
		}
		driver.webhookServer = vaultwebhook.NewServer(webhookCfg, driver.ReconcileSecret)
		go func() {
			if err := driver.webhookServer.Start(); err != nil {
				log.Errorf("Webhook server failed; falling back to polling: %v", err)
				driver.startMonitoring()
			}
		}()
	} else if config.EnableRotation && provider.SupportsRotation() {
		if config.UseWebhook && config.ProviderType != "vault" {
			log.Printf("USE_WEBHOOK=true is ignored for provider %s; falling back to ticker", config.ProviderType)
		}
		log.Printf("Starting secret rotation monitoring with interval: %v", config.RotationInterval)
		go driver.startMonitoring()
	} else if config.EnableRotation {
		log.Warnf("Secret rotation is enabled but provider %s does not support rotation", config.ProviderType)
	} else {
		log.Debug("Secret rotation monitoring is disabled")
	}

	// Start the webhook listener for event-driven rotation (e.g. Doppler).
	if config.WebhookEnable {
		if err := driver.startWebhookServer(); err != nil {
			if cleanupErr := driver.Stop(); cleanupErr != nil {
				log.Warnf("Error cleaning up failed driver initialization: %v", cleanupErr)
			}
			return nil, err
		}
	}

	log.Infof("Successfully initialized driver with %s provider", provider.GetProviderName())
	return driver, nil
}

// startWebhookServer starts the HTTP listener that receives provider webhooks
// (currently Doppler config.secrets.update) and triggers an immediate rotation
// check, bypassing the poll interval.
func (d *SecretsDriver) startWebhookServer() error {
	if !d.config.EnableRotation || !d.provider.SupportsRotation() {
		log.Warnf("DOPPLER_WEBHOOK_ENABLE is set but provider %s cannot rotate (rotation disabled or unsupported); webhook listener will not be started", d.config.ProviderType)
		return nil
	}
	if d.config.DopplerWebhookSecret == "" && !d.config.WebhookAllowUnsigned {
		return fmt.Errorf("DOPPLER_WEBHOOK_SECRET is required when DOPPLER_WEBHOOK_ENABLE=true; set DOPPLER_WEBHOOK_INSECURE=true only for local development")
	}
	if d.config.DopplerWebhookSecret == "" {
		log.Warn("DOPPLER_WEBHOOK_INSECURE=true: Doppler webhook listener will accept unsigned requests")
	}

	addr := fmt.Sprintf(":%d", d.config.DopplerWebhookPort)
	server, err := dopplerwebhook.New(addr, d.config.WebhookPath, d.config.DopplerWebhookSecret, d.config.WebhookAllowUnsigned, d.handleWebhookEvent)
	if err != nil {
		return err
	}
	d.dopplerWebhookServer = server
	if err := d.dopplerWebhookServer.Start(); err != nil {
		return err
	}
	return nil
}

// handleWebhookEvent drops any cached provider secrets and runs a rotation
// check. Invoked asynchronously by the webhook server after authentication.
func (d *SecretsDriver) handleWebhookEvent(_ dopplerwebhook.Payload) {
	if d.monitorCtx.Err() != nil {
		return
	}
	if !d.config.EnableRotation || !d.provider.SupportsRotation() {
		log.Debug("Webhook received but rotation is disabled or unsupported; ignoring")
		return
	}
	if invalidator, ok := d.provider.(providers.CacheInvalidator); ok {
		invalidator.InvalidateCache()
	}
	d.checkForSecretChanges()
}

// buildSecretInfo constructs a SecretInfo from the incoming request, using the
// provider to resolve the secret path. This is the single point where we
// translate a Docker secrets.Request into our internal representation.
func (d *SecretsDriver) buildSecretInfo(req secrets.Request) *providers.SecretInfo {
	secretField := req.SecretLabels[d.provider.GetSecretFieldLabel()]
	if secretField == "" {
		secretField = "value"
	}

	return &providers.SecretInfo{
		DockerSecretName: req.SecretName,
		SecretPath:       d.provider.BuildSecretPath(req), // Start with current service
		SecretField:      secretField,
		ServiceNames:     []string{req.ServiceName},
		Provider:         d.provider.GetProviderName(),
		Labels:           maps.Clone(req.SecretLabels),
	}
}

// Get method implements the secrets.Driver interface
func (d *SecretsDriver) Get(req secrets.Request) secrets.Response {
	log.Debugf("Received secret request for: %s using provider: %s", req.SecretName, d.provider.GetProviderName())

	if req.SecretName == "" {
		log.Warn("Get request rejected: secret name is required")
		return secrets.Response{
			Err: "secret name is required",
		}
	}

	// Build SecretInfo once from the request — used for all downstream calls
	secretInfo := d.buildSecretInfo(req)

	// Add context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get secret from the provider
	value, err := d.provider.GetSecret(ctx, secretInfo)
	if err != nil {
		log.Errorf("Error getting secret from provider %s for secret %s: %v", d.provider.GetProviderName(), req.SecretName, err)
		return secrets.Response{
			Err: fmt.Sprintf("failed to get secret: %v", err),
		}
	}

	// Track this secret for monitoring if rotation is enabled
	if d.config.EnableRotation && d.provider.SupportsRotation() {
		d.trackSecret(secretInfo, value)
	}

	value, err = d.transformSecret(ctx, secretInfo, value)
	if err != nil {
		log.Errorf("Error transforming secret %s: %v", req.SecretName, err)
		return secrets.Response{
			Err: fmt.Sprintf("failed to transform secret: %v", err),
		}
	}

	log.Debugf("Successfully retrieved secret from %s provider", d.provider.GetProviderName())

	// Determine if secret should be reusable (Docker DoNotReuse=true means do not cache/reuse)
	doNotReuse := d.shouldNotReuse(req)
	log.Debugf("Get secret %q: DoNotReuse=%v (Swarm may reuse cached value when false)", req.SecretName, doNotReuse)

	log.Debug("Successfully returning secret value")
	return secrets.Response{
		Value:      value,
		DoNotReuse: doNotReuse,
	}
}

func (d *SecretsDriver) transformSecret(ctx context.Context, secretInfo *providers.SecretInfo, value []byte) ([]byte, error) {
	if d.transformer == nil {
		return value, nil
	}

	transformed, err := d.transformer.Transform(ctx, secretInfo, value)
	if err != nil {
		return nil, fmt.Errorf("transform secret value: %w", err)
	}

	return transformed, nil
}

// shouldNotReuse returns the value for secrets.Response.DoNotReuse.
// When true, Docker should not reuse a cached value (fetch from provider again).
// Label secret_reuse: "true" means allow reuse → DoNotReuse must be false (see docs/multi-provider.md).
func (d *SecretsDriver) shouldNotReuse(req secrets.Request) bool {
	if reuse, exists := req.SecretLabels["secret_reuse"]; exists {
		v := strings.ToLower(strings.TrimSpace(reuse))
		allowReuse := v == "true"
		if allowReuse {
			log.Debugf("secret_reuse=%q for %q: allowing Swarm reuse (DoNotReuse=false)", reuse, req.SecretName)
			return false
		}
		log.Debugf("secret_reuse=%q for %q: disallowing Swarm reuse (DoNotReuse=true)", reuse, req.SecretName)
		return true
	}

	// Don't reuse dynamic secrets or certificates
	if strings.Contains(req.SecretName, "cert") ||
		strings.Contains(req.SecretName, "token") ||
		strings.Contains(req.SecretName, "dynamic") {
		return true
	}

	return false
}

// ReconcileSecret checks every tracked Docker name or Vault path suffix matching
// secretName. Untracked or unchanged secrets require no rotation. It returns
// joined provider/rotation errors, including cancellation, so the webhook can
// request a retry. Successful rotations remain applied if another match fails.
func (d *SecretsDriver) ReconcileSecret(ctx context.Context, secretName string) error {
	d.rotationMu.Lock()
	defer d.rotationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}

	d.trackerMutex.RLock()
	var matches []*providers.SecretInfo
	for trackedName, trackedSecret := range d.secretTracker {
		if trackedName == secretName || strings.HasSuffix(trackedSecret.SecretPath, "/"+secretName) {
			info := *trackedSecret
			info.Labels = maps.Clone(trackedSecret.Labels)
			info.ServiceNames = slices.Clone(trackedSecret.ServiceNames)
			matches = append(matches, &info)
		}
	}
	d.trackerMutex.RUnlock()

	if len(matches) == 0 {
		log.Printf("webhook: secret %q is not currently tracked, skipping", secretName)
		return ctx.Err()
	}

	var failures []error
	for _, info := range matches {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		changed, err := d.hasSecretChanged(ctx, info)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if changed {
			if err := d.handleSecretRotationResult(ctx, info.DockerSecretName, info); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

// trackSecret adds or updates a secret in the tracking system
func (d *SecretsDriver) trackSecret(secretInfo *providers.SecretInfo, value []byte) {
	d.trackerMutex.Lock()
	defer d.trackerMutex.Unlock()

	// Calculate hash for change detection
	hash := fmt.Sprintf("%x", sha256.Sum256(value))

	log.Tracef("Current provider %s tracking secret: %s at path: %s",
		secretInfo.Provider, secretInfo.DockerSecretName, secretInfo.SecretPath)

	// Repeated reads may come from a new consumer while existing services still
	// mount the old value. Only a successful rotation may advance their hash.
	if existing, exists := d.secretTracker[secretInfo.DockerSecretName]; exists {
		// Add service name if not already present
		serviceName := secretInfo.ServiceNames[0]
		serviceFound := slices.Contains(existing.ServiceNames, serviceName)
		if !serviceFound && serviceName != "" {
			existing.ServiceNames = append(existing.ServiceNames, serviceName)
		}
		existing.Labels = secretInfo.Labels
	} else {
		secretInfo.LastHash = hash
		secretInfo.LastUpdated = time.Now()
		d.secretTracker[secretInfo.DockerSecretName] = secretInfo
	}

	log.Tracef("Tracking secret: %s -> %s (provider: %s, services: %v)",
		secretInfo.DockerSecretName, secretInfo.SecretPath, secretInfo.Provider, secretInfo.ServiceNames)
}

// startMonitoring starts the background monitoring goroutine
func (d *SecretsDriver) startMonitoring() {
	ticker := time.NewTicker(d.config.RotationInterval)
	defer ticker.Stop()

	log.Infof("Secret monitoring started with interval: %v", d.config.RotationInterval)

	for {
		select {
		case <-d.monitorCtx.Done():
			log.Info("Secret monitoring stopped")
			return
		case <-ticker.C:
			// Update ticker heartbeat for monitoring
			if d.monitor != nil {
				d.monitor.UpdateTickerHeartbeat()
			}
			d.checkForSecretChanges()
		}
	}
}

// checkForSecretChanges monitors tracked secrets for changes.
// The rotation mutex serializes whole cycles so a webhook-triggered check
// cannot overlap a poll-triggered one (concurrent cycles could interleave the
// create -> update -> remove rotation steps on the same secret).
func (d *SecretsDriver) checkForSecretChanges() {
	d.rotationMu.Lock()
	defer d.rotationMu.Unlock()
	if d.monitorCtx.Err() != nil {
		return
	}

	d.trackerMutex.RLock()
	secrets := make(map[string]*providers.SecretInfo, len(d.secretTracker))
	maps.Copy(secrets, d.secretTracker)
	d.trackerMutex.RUnlock()

	if len(secrets) == 0 {
		log.Debug("No secrets to monitor")
		return
	}

	d.prepareReconciliation(secrets)
	if d.monitorCtx.Err() != nil {
		return
	}

	log.Debugf("Checking %d tracked secrets for changes", len(secrets))
	// TODO: Revisit this limit if secret-label fanout or provider latency changes.
	concurrentSecretChecks := len(secrets) + 1

	sem := make(chan struct{}, concurrentSecretChecks)
	var wg sync.WaitGroup

	for secretName, secretInfo := range secrets {
		sem <- struct{}{}
		wg.Add(1)
		go func(secretName string, secretInfo *providers.SecretInfo) {
			defer wg.Done()
			defer func() { <-sem }()

			changed, err := d.hasSecretChanged(d.monitorCtx, secretInfo)
			if err != nil {
				log.Errorf("Error checking secret change for %s: %v", secretName, err)
				return
			}
			if !changed {
				return
			}

			log.Tracef("Detected change in secret: %s", secretName)
			if err := d.handleSecretRotationResult(d.monitorCtx, secretName, secretInfo); err != nil {
				log.Errorf("Failed to rotate secret %s: %v", secretName, err)
			}
		}(secretName, secretInfo)
	}

	wg.Wait()
}

// prepareReconciliation refreshes provider caches once per cycle. Doppler
// downloads the tracked names for each config in one request, so the checks
// below share that response instead of waiting out DOPPLER_CACHE_TTL.
func (d *SecretsDriver) prepareReconciliation(secrets map[string]*providers.SecretInfo) {
	infos := make([]*providers.SecretInfo, 0, len(secrets))
	for _, info := range secrets {
		infos = append(infos, info)
	}

	if preparer, ok := d.provider.(providers.ReconciliationPreparer); ok {
		ctx, cancel := context.WithTimeout(d.monitorCtx, 30*time.Second)
		defer cancel()
		if err := preparer.PrepareReconciliation(ctx, infos); err != nil {
			log.Errorf("Failed to refresh secrets before rotation check: %v", err)
		}
		return
	}
	if invalidator, ok := d.provider.(providers.CacheInvalidator); ok {
		invalidator.InvalidateCache()
	}
}

func (d *SecretsDriver) handleSecretRotationResult(ctx context.Context, secretName string, secretInfo *providers.SecretInfo) error {
	if err := d.rotateSecret(ctx, secretInfo); err != nil {
		if d.monitor != nil {
			d.monitor.IncrementRotationErrors()
		}
		return fmt.Errorf("rotate secret %s: %w", secretName, err)
	}

	if d.monitor != nil {
		d.monitor.IncrementSecretRotations()
	}
	return nil
}

// hasSecretChanged fetches the current secret value and compares its hash
// against the stored hash to detect changes.
func (d *SecretsDriver) hasSecretChanged(ctx context.Context, secretInfo *providers.SecretInfo) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	currentValue, err := d.provider.GetSecret(ctx, secretInfo)
	if err != nil {
		return false, fmt.Errorf("check secret %s: %w", secretInfo.DockerSecretName, err)
	}

	d.trackerMutex.RLock()
	lastHash := secretInfo.LastHash
	d.trackerMutex.RUnlock()

	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))
	return currentHash != lastHash, nil
}

// rotateSecret handles the secret rotation process
func (d *SecretsDriver) rotateSecret(ctx context.Context, secretInfo *providers.SecretInfo) error {
	log.Infof("Starting rotation for secret: %s", secretInfo.DockerSecretName)

	// Get the new secret value from the provider using the existing SecretInfo
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	providerValue, err := d.provider.GetSecret(fetchCtx, secretInfo)
	if err != nil {
		return fmt.Errorf("failed to get updated secret from provider: %w", err)
	}

	newValue, err := d.transformSecret(fetchCtx, secretInfo, providerValue)
	if err != nil {
		return fmt.Errorf("failed to transform updated secret: %w", err)
	}

	// Update Docker secret (this now handles service updates internally)
	if err := d.updateDockerSecret(ctx, secretInfo.DockerSecretName, newValue); err != nil {
		return fmt.Errorf("failed to update docker secret: %w", err)
	}

	// Update tracking information
	d.trackerMutex.Lock()
	secretInfo.LastHash = fmt.Sprintf("%x", sha256.Sum256(providerValue))
	secretInfo.LastUpdated = time.Now()
	if tracked := d.secretTracker[secretInfo.DockerSecretName]; tracked != nil && tracked != secretInfo {
		tracked.LastHash = secretInfo.LastHash
		tracked.LastUpdated = secretInfo.LastUpdated
	}
	d.trackerMutex.Unlock()

	log.Infof("Successfully rotated secret: %s", secretInfo.DockerSecretName)
	return nil
}

// updateDockerSecret creates a new version of the Docker secret
func (d *SecretsDriver) updateDockerSecret(ctx context.Context, secretName string, newValue []byte) error {
	dockerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// List existing secrets to find the one to update
	secrets, err := d.dockerClient.SecretList(dockerCtx, swarm.SecretListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	var existingSecret *swarm.Secret
	for _, secret := range secrets {
		if secret.Spec.Name == secretName {
			existingSecret = &secret
			break
		}
	}

	if existingSecret == nil {
		return fmt.Errorf("secret %s not found", secretName)
	}

	// Generate a unique name for the new secret version
	newSecretName := fmt.Sprintf("%s-%d", secretName, time.Now().UnixNano())

	// Create new secret with versioned name and same labels but updated value
	newSecretSpec := swarm.SecretSpec{
		Annotations: swarm.Annotations{
			Name:   newSecretName,
			Labels: existingSecret.Spec.Labels,
		},
		Data: newValue,
	}

	// Create the new secret
	createResponse, err := d.dockerClient.SecretCreate(dockerCtx, newSecretSpec)
	if err != nil {
		return fmt.Errorf("failed to create new secret version: %w", err)
	}

	log.Infof("Created new version of secret %s with name %s and ID: %s", secretName, newSecretName, createResponse.ID)

	// Update all services that use this secret to point to the new version
	if err := d.updateServicesSecretReference(ctx, secretName, existingSecret.ID, newSecretName, createResponse.ID); err != nil {
		// Rollback must still run when shutdown cancels reconciliation.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cleanupCancel()
		if cleanupErr := d.dockerClient.SecretRemove(cleanupCtx, createResponse.ID); cleanupErr != nil {
			log.Warnf("failed to remove new secret %s after service update error: %v", createResponse.ID, cleanupErr)
		}
		return fmt.Errorf("failed to update services to use new secret: %w", err)
	}

	// Remove the old secret only after services are updated
	if err := d.dockerClient.SecretRemove(dockerCtx, existingSecret.ID); err != nil {
		log.Warnf("Failed to remove old secret version %s: %v", existingSecret.ID, err)
		// Don't return error as the new secret was created and services updated successfully
	}

	return nil
}

// updateServicesSecretReference updates all services to use the new secret version
func (d *SecretsDriver) updateServicesSecretReference(ctx context.Context, oldSecretName, oldSecretID, newSecretName, newSecretID string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// List all services
	services, err := d.dockerClient.ServiceList(ctx, swarm.ServiceListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	var updatedServices []string

	for _, service := range services {
		// Check if service uses this secret and update the reference.
		containerSpec := service.Spec.TaskTemplate.ContainerSpec
		if containerSpec == nil {
			log.Warnf("Skipping secret update for service %s: TaskTemplate.ContainerSpec is nil", service.Spec.Name)
			continue
		}

		updatedSecrets := make([]*swarm.SecretReference, len(containerSpec.Secrets))
		needsUpdate := buildUpdatedSecretReferences(
			containerSpec.Secrets,
			oldSecretName,
			oldSecretID,
			newSecretName,
			newSecretID,
			updatedSecrets,
		)
		if needsUpdate {
			if err := d.applyServiceSecretUpdate(ctx, service, updatedSecrets); err != nil {
				return err
			}
			updatedServices = append(updatedServices, service.Spec.Name)
		}
	}

	if len(updatedServices) > 0 {
		log.Infof("Updated services to use new secret %s: %v", newSecretName, updatedServices)
	}

	return nil
}

func buildUpdatedSecretReferences(
	secretRefs []*swarm.SecretReference,
	oldSecretName string,
	oldSecretID string,
	newSecretName string,
	newSecretID string,
	updatedSecrets []*swarm.SecretReference,
) bool {
	needsUpdate := false
	for i, secretRef := range secretRefs {
		if secretRef == nil {
			continue
		}

		if (oldSecretID != "" && secretRef.SecretID == oldSecretID) || secretRef.SecretName == oldSecretName {
			// Update to use the new secret name and ID.
			updatedSecrets[i] = &swarm.SecretReference{
				File:       secretRef.File,
				SecretID:   newSecretID, // Use actual Docker secret ID
				SecretName: newSecretName,
			}
			needsUpdate = true
			continue
		}

		updatedSecrets[i] = secretRef
	}

	return needsUpdate
}

func (d *SecretsDriver) applyServiceSecretUpdate(
	ctx context.Context,
	service swarm.Service,
	updatedSecrets []*swarm.SecretReference,
) error {
	serviceSpec := service.Spec
	if serviceSpec.TaskTemplate.ContainerSpec == nil {
		log.Warnf("Skipping secret update for service %s: TaskTemplate.ContainerSpec is nil", service.Spec.Name)
		return nil
	}

	// Update service with new secret references.
	serviceSpec.TaskTemplate.ContainerSpec.Secrets = updatedSecrets

	if serviceSpec.Labels == nil {
		serviceSpec.Labels = make(map[string]string)
	}

	// Add/update a label to force the update.
	serviceSpec.Labels["vault.secret.rotated"] = fmt.Sprintf("%d", time.Now().Unix())

	updateResponse, err := d.dockerClient.ServiceUpdate(ctx, service.ID, service.Version, serviceSpec, swarm.ServiceUpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update service %s: %w", service.Spec.Name, err)
	}

	if len(updateResponse.Warnings) > 0 {
		log.Warnf("Service update warnings for %s: %v", service.Spec.Name, updateResponse.Warnings)
	}

	return nil
}

// Stop gracefully stops the monitoring and cleans up resources
func (d *SecretsDriver) Stop() error {
	if d.monitorCancel != nil {
		d.monitorCancel()
	}

	if d.monitor != nil {
		d.monitor.Stop()
	}

	if d.webInterface != nil {
		if err := d.webInterface.Stop(); err != nil {
			log.Warnf("Error stopping web interface: %v", err)
		}
	}

	if d.webhookServer != nil {
		if err := d.webhookServer.Stop(); err != nil {
			log.Warnf("Error stopping webhook server: %v", err)
		}
	}

	if d.dopplerWebhookServer != nil {
		if err := d.dopplerWebhookServer.Stop(); err != nil {
			log.Warnf("Error stopping Doppler webhook server: %v", err)
		}
	}

	// Rotation calls use monitorCtx, so cancellation lets active work finish
	// before the provider and Docker client are closed. Queued cycles see the
	// canceled context and return without accessing these resources.
	d.rotationMu.Lock()
	defer d.rotationMu.Unlock()

	if d.provider != nil {
		if err := d.provider.Close(); err != nil {
			log.Warnf("Error closing provider: %v", err)
		}
	}

	if d.dockerClient != nil {
		return d.dockerClient.Close()
	}
	return nil
}
