package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ReconcileFunc is the callback signature that the driver exposes so that both
// the existing ticker and the new webhook path can share the same
// fetch-and-update logic.
// The function receives the Docker secret name that needs to be reconciled.
type ReconcileFunc func(ctx context.Context, secretName string) error

const (
	maxWebhookBodyBytes     = 1 << 20
	webhookReconcileTimeout = 2 * time.Minute
)

// HCP Vault Secrets webhook payload types -----

// WebhookPayload represents the top-level structure of an HCP Vault Secrets
// webhook event.  Only the fields the plugin cares about are kept; unknown
// fields are silently ignored by encoding/json.
type WebhookPayload struct {
	EventID          string              `json:"event_id"`
	EventAction      string              `json:"event_action"`
	EventDescription string              `json:"event_description"`
	EventSource      string              `json:"event_source"`
	EventVersion     string              `json:"event_version"`
	ResourceID       string              `json:"resource_id"`
	ResourceName     string              `json:"resource_name"`
	EventPayload     WebhookEventPayload `json:"event_payload"`
}

// WebhookEventPayload holds the inner payload shipped inside every HCP webhook
// event.  The "name" field carries the human-readable secret name.
type WebhookEventPayload struct {
	AppName        string `json:"app_name"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	PrincipalID    string `json:"principal_id"`
	Provider       string `json:"provider"`
	Timestamp      string `json:"timestamp"`
	Type           string `json:"type"`
	Version        int    `json:"version"`
}

// WebhookConfig holds the user-supplied configuration for the webhook listener.
type WebhookConfig struct {
	// Port on which the HTTP listener binds (default 9095).
	Port int
	// Secret is the HMAC token shared with HCP.  When non-empty every
	// incoming request MUST carry a valid X-HCP-Webhook-Signature header.
	WebhookSecret string
}

// WebhookServer is an HTTP server that receives push events from HCP Vault
// Secrets and triggers secret reconciliation through the shared ReconcileFunc.
type WebhookServer struct {
	config    *WebhookConfig
	reconcile ReconcileFunc
	server    *http.Server
	ctx       context.Context
	cancel    context.CancelFunc
	workMu    sync.Mutex
	stopping  bool
	work      sync.WaitGroup
	active    chan struct{}
}

// actionable is the set of HCP event actions that should trigger a
// reconciliation.  "test" is the HCP verification ping — we accept it but
// do not reconcile.
var actionable = map[string]bool{
	"create": true,
	"update": true,
	"rotate": true,
}

// NewWebhookServer creates a ready-to-start webhook server.
func NewWebhookServer(cfg *WebhookConfig, reconcile ReconcileFunc) *WebhookServer {
	mux := http.NewServeMux()
	ctx, cancel := context.WithCancel(context.Background())

	ws := &WebhookServer{
		config:    cfg,
		reconcile: reconcile,
		ctx:       ctx,
		cancel:    cancel,
		active:    make(chan struct{}, 1),
		server: &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.Port),
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      webhookReconcileTimeout + 15*time.Second,
		},
	}

	mux.HandleFunc("/webhook", ws.handleWebhook)
	mux.HandleFunc("/webhook/health", ws.handleHealth)

	return ws
}

// Start begins listening.  This method blocks; call it in a goroutine.
func (ws *WebhookServer) Start() error {
	if ws.config.WebhookSecret == "" {
		log.Warn("Webhook secret is unset; webhook requests are unauthenticated")
	}
	log.Printf("Webhook server listening on %s", ws.server.Addr)
	if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Errorf("Webhook server error: %v", err)
		return err
	}
	return nil
}

// Stop gracefully shuts the server down.
func (ws *WebhookServer) Stop() error {
	ws.workMu.Lock()
	ws.stopping = true
	ws.cancel()
	ws.workMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := ws.server.Shutdown(ctx)
	if err != nil {
		_ = ws.server.Close()
	}
	done := make(chan struct{})
	go func() {
		ws.work.Wait()
		close(done)
	}()
	select {
	case <-done:
		return err
	case <-ctx.Done():
		if err != nil {
			return err
		}
		return ctx.Err()
	}
}

// HTTP handlers

func (ws *WebhookServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the raw body (needed for HMAC validation before unmarshalling).
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Errorf("webhook: failed to close request body: %v", err)
		}
	}()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes))
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		log.Errorf("webhook: failed to read request body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// HMAC validation
	if ws.config.WebhookSecret != "" {
		sig := r.Header.Get("X-HCP-Webhook-Signature")
		if sig == "" {
			log.Warn("webhook: missing X-HCP-Webhook-Signature header")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !ws.verifyHMAC(body, sig) {
			log.Warn("webhook: HMAC signature mismatch")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Parse payload
	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Errorf("webhook: failed to parse payload: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("webhook: received event_action=%s event_source=%s secret=%s",
		payload.EventAction, payload.EventSource, payload.EventPayload.Name)

	// HCP verification ping
	if strings.EqualFold(payload.EventAction, "test") {
		log.Info("webhook: responding to HCP verification ping")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Filter to actionable secret events
	if !isSecretEvent(payload.EventSource) {
		log.Printf("webhook: ignoring non-secret event source: %s", payload.EventSource)
		w.WriteHeader(http.StatusOK)
		return
	}

	if !actionable[strings.ToLower(payload.EventAction)] {
		log.Printf("webhook: ignoring event_action=%s", payload.EventAction)
		w.WriteHeader(http.StatusOK)
		return
	}

	secretName := payload.EventPayload.Name
	if secretName == "" {
		log.Warn("webhook: event has no secret name in payload, skipping")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Admit one reconciliation at a time so duplicate events cannot rotate
	// the same Docker secret concurrently.
	ws.workMu.Lock()
	if ws.stopping {
		ws.workMu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	select {
	case ws.active <- struct{}{}:
	default:
		ws.workMu.Unlock()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "reconciliation busy", http.StatusServiceUnavailable)
		return
	}
	ws.work.Add(1)
	ws.workMu.Unlock()
	defer ws.work.Done()
	defer func() { <-ws.active }()

	ctx, cancel := context.WithTimeout(r.Context(), webhookReconcileTimeout)
	defer cancel()
	stopCancel := context.AfterFunc(ws.ctx, cancel)
	defer stopCancel()

	log.Printf("webhook: reconciling secret %q (action=%s)", secretName, payload.EventAction)
	err = ws.reconcile(ctx, secretName)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		log.Errorf("webhook: reconciliation failed for %q: %v", secretName, err)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "reconciliation failed", http.StatusServiceUnavailable)
		return
	}

	log.Printf("webhook: successfully reconciled secret %q", secretName)
	w.WriteHeader(http.StatusOK)
}

func (ws *WebhookServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","webhook_enabled":true}`)
}

// Helpers

// verifyHMAC checks the X-HCP-Webhook-Signature header against the raw body.
// HCP uses HMAC-SHA256 with the shared token to compute the hex-encoded
// signature.
func (ws *WebhookServer) verifyHMAC(body []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(ws.config.WebhookSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks.
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(signature)))
}

// isSecretEvent returns true when the event_source indicates a secret
// lifecycle event as opposed to app or integration events.
//
// HCP Vault Secrets uses these event_source values:
//   - "hashicorp.secrets.secret"      → secret lifecycle (we care about this)
//   - "hashicorp.secrets.app"         → application lifecycle (ignore)
//   - "hashicorp.secrets.integration" → integration lifecycle (ignore)
func isSecretEvent(source string) bool {
	return strings.EqualFold(source, "hashicorp.secrets.secret")
}
