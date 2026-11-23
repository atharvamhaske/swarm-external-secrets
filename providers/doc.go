// Package providers implements secret backends for the Docker Swarm plugin.
// CreateProvider selects a backend; callers initialize it before reading secrets
// and call Close when finished. The legacy webhook API forwards to the receiver
// in internal/webhook/vault; notification handling is separate from backends.
package providers
