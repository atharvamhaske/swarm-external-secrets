// Package vault implements the plugin's Vault webhook receiver.
// Callers supply the reconciliation callback and configure an upstream event
// sender separately. The current HMAC-SHA256 signature validator does not accept
// HCP's documented HMAC-SHA512 signatures.
package vault
