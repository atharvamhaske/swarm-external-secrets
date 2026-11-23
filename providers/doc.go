// Package providers implements secret backends for the Docker Swarm plugin.
// CreateProvider selects a backend; callers initialize it before reading secrets
// and call Close when finished. WebhookServer receives notifications separately
// from backend authentication and does not configure an upstream event sender.
package providers
