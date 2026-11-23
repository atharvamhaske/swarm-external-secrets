package providers

import vaultwebhook "github.com/sciops-org/swarm-external-secrets/internal/webhook/vault"

// ReconcileFunc preserves the provider package's webhook callback API.
type ReconcileFunc = vaultwebhook.ReconcileFunc

// WebhookPayload preserves the provider package's webhook payload API.
type WebhookPayload = vaultwebhook.Payload

// WebhookEventPayload preserves the provider package's event payload API.
type WebhookEventPayload = vaultwebhook.EventPayload

// WebhookConfig preserves the provider package's webhook configuration API.
type WebhookConfig = vaultwebhook.Config

// WebhookServer preserves the provider package's webhook server API.
type WebhookServer = vaultwebhook.Server

// NewWebhookServer forwards to the internal Vault webhook receiver.
// cfg and reconcile follow the contract of vaultwebhook.NewServer.
func NewWebhookServer(cfg *WebhookConfig, reconcile ReconcileFunc) *WebhookServer {
	return vaultwebhook.NewServer(cfg, reconcile)
}
