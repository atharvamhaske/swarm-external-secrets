package vault

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

// ReconcileFunc checks tracked secrets matching an event's secret name.
// The listener calls it synchronously and acknowledges success only when it
// returns nil. Implementations must honor ctx cancellation and deadlines.
type ReconcileFunc func(ctx context.Context, secretName string) error

const (
	maxWebhookBodyBytes     = 1 << 20
	webhookReconcileTimeout = 2 * time.Minute
)

// Payload is the HCP-style JSON envelope accepted by the listener.
// EventAction, EventSource, and EventPayload.Name control reconciliation;
// other metadata does not select a Vault namespace or application. Unknown
// JSON fields are ignored. This envelope alone does not establish HCP compatibility.
type Payload struct {
	EventID          string       `json:"event_id"`
	EventAction      string       `json:"event_action"`
	EventDescription string       `json:"event_description"`
	EventSource      string       `json:"event_source"`
	EventVersion     string       `json:"event_version"`
	ResourceID       string       `json:"resource_id"`
	ResourceName     string       `json:"resource_name"`
	EventPayload     EventPayload `json:"event_payload"`
}

// EventPayload holds the event's secret name and optional metadata.
// Name is matched against tracked Docker names and Vault path suffixes.
type EventPayload struct {
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

// Config configures the HTTP listener. The driver supplies defaults;
// NewServer uses the supplied values without applying defaults.
type Config struct {
	// Port is the TCP listener port on all interfaces; the driver defaults to 9095.
	Port int
	// WebhookSecret is the shared token for the current HMAC-SHA256 validator.
	// A nonempty token requires X-HCP-Webhook-Signature on POST /webhook, including
	// verification pings. Empty disables authentication and Start logs a warning.
	WebhookSecret string
}

// Server receives HCP-style notifications and reconciles one request at
// a time. It provides no Vault-side event subscription. The current SHA-256
// signature validator is incompatible with HCP's documented SHA-512 signatures.
type Server struct {
	config    *Config
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

// NewServer prepares /webhook and /webhook/health without binding a port.
// cfg and reconcile must be non-nil; callers must not mutate cfg during use.
// Call Start to listen and Stop to cancel and drain in-flight reconciliation.
func NewServer(cfg *Config, reconcile ReconcileFunc) *Server {
	mux := http.NewServeMux()
	ctx, cancel := context.WithCancel(context.Background())

	ws := &Server{
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

// Start listens until Stop is called or the HTTP server fails. It returns
// listener/server errors and treats normal shutdown as success. Call it in a
// goroutine when the caller must continue serving the Docker plugin socket.
func (ws *Server) Start() error {
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

// Stop cancels in-flight reconciliation and drains HTTP requests and callbacks
// for up to five seconds. It returns an error if shutdown or draining times out.
// A stopped server cannot be restarted.
func (ws *Server) Stop() error {
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

func (ws *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
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
	var payload Payload
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

func (ws *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok","webhook_enabled":true}`)
}

// Helpers

// verifyHMAC checks the X-HCP-Webhook-Signature header against the raw body.
// This implementation uses HMAC-SHA256; HCP documents HMAC-SHA512, so direct
// HCP signatures are not compatible with the current validator.
func (ws *Server) verifyHMAC(body []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(ws.config.WebhookSecret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks.
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(signature)))
}

// isSecretEvent returns true when the event_source indicates a secret
// lifecycle event as opposed to app or integration events.
//
// The listener accepts "hashicorp.secrets.secret" and ignores other sources.
func isSecretEvent(source string) bool {
	return strings.EqualFold(source, "hashicorp.secrets.secret")
}
