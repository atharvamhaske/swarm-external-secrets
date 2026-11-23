package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookServer_StopCancelsReconciliation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	finished := make(chan struct{})
	ws := NewWebhookServer(&WebhookConfig{}, func(ctx context.Context, name string) error {
		defer close(finished)
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	t.Cleanup(func() { _ = ws.Stop() })

	body := `{"event_action":"rotate","event_source":"hashicorp.secrets.secret","event_payload":{"name":"mysql"}}`
	recorder := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		ws.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body)))
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("reconciliation did not start")
	}
	if err := ws.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("Stop returned before reconciliation finished")
	}
	<-requestDone
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status on cancellation = %d, want 503", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	ws.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after Stop = %d, want 503", recorder.Code)
	}
}

func TestWebhookServer_Authentication(t *testing.T) {
	t.Parallel()
	body := `{"event_action":"test"}`
	mac := hmac.New(sha256.New, []byte("shared-secret"))
	_, _ = mac.Write([]byte(body))
	signature := hex.EncodeToString(mac.Sum(nil))
	tests := []struct {
		name      string
		secret    string
		signature string
		want      int
	}{
		{name: "optional secret", want: http.StatusOK},
		{name: "missing signature", secret: "shared-secret", want: http.StatusUnauthorized},
		{name: "invalid signature", secret: "shared-secret", signature: "invalid", want: http.StatusUnauthorized},
		{name: "valid signature", secret: "shared-secret", signature: signature, want: http.StatusOK},
		{name: "uppercase signature", secret: "shared-secret", signature: strings.ToUpper(signature), want: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ws := NewWebhookServer(&WebhookConfig{WebhookSecret: tt.secret}, nil)
			t.Cleanup(func() { _ = ws.Stop() })
			req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
			req.Header.Set("X-HCP-Webhook-Signature", tt.signature)
			recorder := httptest.NewRecorder()
			ws.server.Handler.ServeHTTP(recorder, req)
			if recorder.Code != tt.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.want)
			}
		})
	}
}

func TestWebhookServer_RejectsOversizedBody(t *testing.T) {
	t.Parallel()
	ws := NewWebhookServer(&WebhookConfig{}, nil)
	t.Cleanup(func() { _ = ws.Stop() })
	recorder := httptest.NewRecorder()
	ws.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/webhook",
		strings.NewReader(strings.Repeat(" ", 1024*1024+1))))
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", recorder.Code)
	}
}

func TestWebhookServer_StopCancelsBeforeDrainingHTTP(t *testing.T) {
	t.Parallel()
	ws := NewWebhookServer(&WebhookConfig{}, nil)
	t.Cleanup(func() { _ = ws.Stop() })
	started := make(chan struct{})
	ws.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-ws.ctx.Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = ws.server.Serve(listener)
	}()
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		client := &http.Client{Timeout: 10 * time.Second}
		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request did not start")
	}
	if err := ws.Stop(); err != nil {
		t.Fatalf("shutdown did not cancel work before draining HTTP: %v", err)
	}
	<-serveDone
	<-requestDone
}

func TestWebhookServer_RejectsOverlappingReconciliation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	ws := NewWebhookServer(&WebhookConfig{}, func(ctx context.Context, name string) error {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	t.Cleanup(func() { _ = ws.Stop() })
	body := `{"event_action":"rotate","event_source":"hashicorp.secrets.secret","event_payload":{"name":"mysql"}}`
	first := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		ws.server.Handler.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body)))
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("reconciliation did not start")
	}
	second := httptest.NewRecorder()
	ws.server.Handler.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body)))
	if second.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("overlapping request status = %d, callback count = %d; want 503 and 1", second.Code, calls.Load())
	}
	close(release)
	<-firstDone
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", first.Code)
	}
}

func TestWebhookServer_ReturnsReconciliationFailure(t *testing.T) {
	t.Parallel()
	ws := NewWebhookServer(&WebhookConfig{}, func(ctx context.Context, name string) error {
		return errors.New("provider unavailable")
	})
	t.Cleanup(func() { _ = ws.Stop() })
	body := `{"event_action":"rotate","event_source":"hashicorp.secrets.secret","event_payload":{"name":"mysql"}}`
	recorder := httptest.NewRecorder()
	ws.server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body)))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("failed reconciliation response = %d, headers = %v; want retryable 503", recorder.Code, recorder.Header())
	}
}

func TestWebhookServer_CancelsWithRequest(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	ws := NewWebhookServer(&WebhookConfig{}, func(ctx context.Context, name string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	t.Cleanup(func() { _ = ws.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := `{"event_action":"rotate","event_source":"hashicorp.secrets.secret","event_payload":{"name":"mysql"}}`
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body)).WithContext(ctx)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ws.server.Handler.ServeHTTP(recorder, req)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("reconciliation did not start")
	}
	cancel()
	select {
	case <-done:
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("status after client cancellation = %d, want 503", recorder.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconciliation ignored request cancellation")
	}
}
