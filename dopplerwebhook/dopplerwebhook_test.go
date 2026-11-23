package dopplerwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestServer_VerifySignature(t *testing.T) {
	body := []byte(`{"type":"config.secrets.update"}`)

	tests := []struct {
		name   string
		secret string
		header string
		want   bool
	}{
		{
			name:   "unsigned allowed when explicitly enabled",
			secret: "",
			header: "",
			want:   true,
		},
		{
			name:   "valid signature",
			secret: "whsec",
			header: sign("whsec", string(body)),
			want:   true,
		},
		{
			name:   "wrong secret",
			secret: "whsec",
			header: sign("other", string(body)),
			want:   false,
		},
		{
			name:   "missing signature with secret set",
			secret: "whsec",
			header: "",
			want:   false,
		},
		{
			name:   "missing sha256 prefix but correct hex",
			secret: "whsec",
			header: strings.TrimPrefix(sign("whsec", string(body)), "sha256="),
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowUnsigned := tt.secret == ""
			s, err := New(":0", "/webhooks/doppler", tt.secret, allowUnsigned, nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if got := s.verifySignature(tt.header, body); got != tt.want {
				t.Fatalf("verifySignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRequiresSigningSecret(t *testing.T) {
	_, err := New(":0", "/webhooks/doppler", "", false, nil)
	if err == nil {
		t.Fatal("New() error = nil, want missing signing secret")
	}
}

func TestNewRejectsPathWithoutSlash(t *testing.T) {
	_, err := New(":0", "webhooks/doppler", "whsec", false, nil)
	if err == nil {
		t.Fatal("New() error = nil, want path rejected")
	}
}

func TestStartReturnsBindError(t *testing.T) {
	s, err := New("127.0.0.1:-1", "/webhooks/doppler", "whsec", false, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("Start() error = nil, want bind error")
	}
}

func TestServer_HandleTriggersEvent(t *testing.T) {
	const secret = "whsec"
	body := `{"type":"config.secrets.update","diff":{"updated":["FOO"]}}`

	var (
		mu     sync.Mutex
		called bool
	)
	done := make(chan struct{})
	onEvent := func(_ Payload) {
		mu.Lock()
		called = true
		mu.Unlock()
		close(done)
	}

	resp := postWebhook(t, secret, onEvent, http.MethodPost, body, sign(secret, body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onEvent was not invoked")
	}

	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Fatal("expected onEvent to be called")
	}
}

func TestServer_HandleRejectsBadSignature(t *testing.T) {
	const secret = "whsec"
	body := `{"type":"config.secrets.update"}`

	called := false
	onEvent := func(_ Payload) { called = true }

	resp := postWebhook(t, secret, onEvent, http.MethodPost, body, sign("wrong-secret", body))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	// Give any (erroneously) spawned goroutine a chance to run.
	time.Sleep(100 * time.Millisecond)
	if called {
		t.Fatal("onEvent should not be called for an invalid signature")
	}
}

// TestServer_HandleStatusAndDispatch exercises method, signature, body, and
// type-filtering paths through the handler, asserting both the HTTP status and
// whether onEvent fires.
func TestServer_HandleStatusAndDispatch(t *testing.T) {
	const secret = "whsec"

	tests := []struct {
		name       string
		method     string
		body       string
		sign       bool   // sign with the correct secret
		signature  string // explicit signature header (overrides sign)
		wantStatus int
		wantEvent  bool
	}{
		{
			name:       "non-POST method rejected",
			method:     http.MethodGet,
			body:       `{"type":"config.secrets.update"}`,
			sign:       true,
			wantStatus: http.StatusMethodNotAllowed,
			wantEvent:  false,
		},
		{
			name:       "missing signature header with secret set",
			method:     http.MethodPost,
			body:       `{"type":"config.secrets.update"}`,
			signature:  "",
			wantStatus: http.StatusUnauthorized,
			wantEvent:  false,
		},
		{
			name:       "empty body with valid signature is invalid payload",
			method:     http.MethodPost,
			body:       "",
			sign:       true,
			wantStatus: http.StatusBadRequest,
			wantEvent:  false,
		},
		{
			name:       "malformed json rejected",
			method:     http.MethodPost,
			body:       `{"type":`,
			sign:       true,
			wantStatus: http.StatusBadRequest,
			wantEvent:  false,
		},
		{
			name:       "non-matching type is ignored",
			method:     http.MethodPost,
			body:       `{"type":"config.secrets.delete"}`,
			sign:       true,
			wantStatus: http.StatusOK,
			wantEvent:  false,
		},
		{
			name:       "omitted type triggers event",
			method:     http.MethodPost,
			body:       `{"diff":{"updated":["FOO"]}}`,
			sign:       true,
			wantStatus: http.StatusOK,
			wantEvent:  true,
		},
		{
			name:       "matching type triggers event",
			method:     http.MethodPost,
			body:       `{"type":"config.secrets.update","diff":{"updated":["FOO"]}}`,
			sign:       true,
			wantStatus: http.StatusOK,
			wantEvent:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			done := make(chan struct{}, 1)
			onEvent := func(_ Payload) { done <- struct{}{} }

			sig := ""
			switch {
			case tt.sign:
				sig = sign(secret, tt.body)
			case tt.signature != "":
				sig = tt.signature
			}
			resp := postWebhook(t, secret, onEvent, tt.method, tt.body, sig)

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			if tt.wantEvent {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("expected onEvent to be invoked")
				}
				return
			}

			select {
			case <-done:
				t.Fatal("onEvent should not have been invoked")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// Oversized requests must be rejected before signature verification or dispatch.
func TestServer_HandleRejectsOversizedBody(t *testing.T) {
	const secret = "whsec"

	// Build a valid JSON payload padded past the read cap.
	padding := strings.Repeat("A", maxBodyBytes+1024)
	body := `{"type":"config.secrets.update","pad":"` + padding + `"}`

	called := false
	onEvent := func(_ Payload) { called = true }

	// Even a correctly signed request must respect the body-size limit.
	resp := postWebhook(t, secret, onEvent, http.MethodPost, body, sign(secret, body))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}

	time.Sleep(100 * time.Millisecond)
	if called {
		t.Fatal("onEvent should not be called when the body is oversized")
	}
}

func postWebhook(t *testing.T, secret string, onEvent func(Payload), method, body, signature string) *http.Response {
	t.Helper()
	s, err := New(":0", "/webhooks/doppler", secret, false, onEvent)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	srv := httptest.NewServer(s.server.Handler)
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+"/webhooks/doppler", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if signature != "" {
		req.Header.Set(signatureHeader, signature)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestNewRejectsRoutePatterns(t *testing.T) {
	for _, path := range []string{"/{", "/foo}", "/{secret}", "/webhooks doppler", "/webhooks\tdoppler"} {
		t.Run(path, func(t *testing.T) {
			if _, err := New(":0", path, "whsec", false, nil); err == nil {
				t.Fatalf("New(%q) error = nil, want invalid literal path", path)
			}
		})
	}
}

func TestServerCoalescesBurst(t *testing.T) {
	started := make(chan Payload, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int32
	s, err := New(":0", defaultPath, "", true, func(payload Payload) {
		started <- payload
		if calls.Add(1) == 1 {
			<-release
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		releaseOnce.Do(func() { close(release) })
		if err := s.Stop(); err != nil {
			t.Error(err)
		}
	}()
	if !s.dispatch(Payload{Type: "first"}) {
		t.Fatal("first event was not accepted")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first callback did not start")
	}
	for range 100 {
		if !s.dispatch(Payload{Type: "intermediate"}) {
			t.Fatal("event was not accepted")
		}
	}
	if !s.dispatch(Payload{Type: "latest"}) {
		t.Fatal("last event was not accepted")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callbacks running during blocked first callback = %d, want 1", got)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case payload := <-started:
		if payload.Type != "latest" {
			t.Fatalf("pending payload = %q, want latest", payload.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("pending callback did not start")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("callback count = %d, want 2", got)
	}
}

func TestServerStopJoinsCallbackAndDiscardsPending(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int32
	s, err := New(":0", defaultPath, "", true, func(Payload) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	if !s.dispatch(Payload{}) {
		t.Fatal("event was not accepted")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	if !s.dispatch(Payload{}) {
		t.Fatal("pending event was not accepted")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop() }()
	deadline := time.After(time.Second)
	for {
		s.eventMu.Lock()
		stopping := s.stopped
		s.eventMu.Unlock()
		if stopping {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Stop did not begin")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case err := <-stopped:
		t.Fatalf("Stop returned before the active callback completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, defaultPath, strings.NewReader(`{"type":"config.secrets.update"}`))
	s.handle(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("dispatch after Stop status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not join callback")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback count after Stop = %d, want 1", got)
	}
}
