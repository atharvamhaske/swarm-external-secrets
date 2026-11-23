package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types/swarm"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sciops-org/swarm-external-secrets/providers"
)

func TestNewDriver_WebhookFailureFallsBackToPolling(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	reads := make(chan struct{}, 1)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reads <- struct{}{}:
		default:
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"unchanged"}}}`))
	}))
	defer vault.Close()
	t.Setenv("SECRETS_PROVIDER", "vault")
	t.Setenv("VAULT_ADDR", vault.URL)
	t.Setenv("VAULT_AUTH_METHOD", "token")
	t.Setenv("VAULT_TOKEN", "test-token")
	t.Setenv("VAULT_KV_VERSION", "2")
	t.Setenv("ENABLE_MONITORING", "false")
	t.Setenv("ENABLE_ROTATION", "true")
	t.Setenv("ROTATION_INTERVAL", "10ms")
	t.Setenv("USE_WEBHOOK", "true")
	t.Setenv("WEBHOOK_PORT", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	driver, err := NewDriver()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = driver.Stop() }()
	driver.trackSecret(&providers.SecretInfo{
		DockerSecretName: "mysql", SecretPath: "secret/data/mysql", SecretField: "value",
	}, []byte("unchanged"))
	select {
	case <-reads:
	case <-time.After(5 * time.Second):
		t.Fatal("failed webhook listener did not fall back to polling")
	}
}

func TestNewDriver_VaultAliasesUseWebhook(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("VAULT_AUTH_METHOD", "token")
	t.Setenv("VAULT_TOKEN", "test-token")
	t.Setenv("VAULT_KV_VERSION", "2")
	t.Setenv("ENABLE_MONITORING", "false")
	t.Setenv("ENABLE_ROTATION", "true")
	t.Setenv("ROTATION_INTERVAL", "1h")
	t.Setenv("USE_WEBHOOK", "true")
	t.Setenv("WEBHOOK_SECRET", "test-webhook-secret")
	t.Setenv("WEBHOOK_PORT", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	for _, providerType := range []string{"vault", "VAULT", "hashicorp-vault", "HASHICORP-VAULT"} {
		t.Run(providerType, func(t *testing.T) {
			t.Setenv("SECRETS_PROVIDER", providerType)
			driver, err := NewDriver()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = driver.Stop() }()
			if driver.webhookServer == nil {
				t.Fatalf("provider %q selected Vault but did not configure the webhook listener", providerType)
			}
			if driver.config.ProviderType != "vault" {
				t.Fatalf("provider type = %q, want canonical name vault", driver.config.ProviderType)
			}
		})
	}
}

func TestNewDriver_DopplerWebhookSettingsAreIndependent(t *testing.T) {
	vaultListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vaultListener.Close() })
	_, vaultPort, err := net.SplitHostPort(vaultListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dopplerListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, dopplerPort, err := net.SplitHostPort(dopplerListener.Addr().String())
	_ = dopplerListener.Close()
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"SECRETS_PROVIDER": "doppler", "DOPPLER_TOKEN": "dp.st.test",
		"ENABLE_MONITORING": "false", "ENABLE_ROTATION": "true", "ROTATION_INTERVAL": "1h",
		"USE_WEBHOOK": "true", "WEBHOOK_PORT": vaultPort, "WEBHOOK_SECRET": "vault-only",
		"DOPPLER_WEBHOOK_ENABLE": "true", "DOPPLER_WEBHOOK_PORT": dopplerPort,
		"DOPPLER_WEBHOOK_PATH": "/webhooks/doppler", "DOPPLER_WEBHOOK_SECRET": "doppler-only",
		"DOPPLER_WEBHOOK_INSECURE": "false",
	} {
		t.Setenv(key, value)
	}
	driver, err := NewDriver()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Stop() })
	if driver.dopplerWebhookServer == nil || driver.webhookServer != nil {
		t.Fatal("Doppler should use its own listener and ignore the Vault webhook flag")
	}
	const payload = `{"type":"ignored"}`
	client := &http.Client{Timeout: 2 * time.Second}
	for _, tt := range []struct {
		name string
		key  string
		want int
	}{
		{name: "Doppler signing secret", key: "doppler-only", want: http.StatusOK},
		{name: "Vault secret must not authenticate Doppler", key: "vault-only", want: http.StatusUnauthorized},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mac := hmac.New(sha256.New, []byte(tt.key))
			_, _ = mac.Write([]byte(payload))
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				"http://127.0.0.1:"+dopplerPort+"/webhooks/doppler", strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Doppler-Signature", fmt.Sprintf("sha256=%x", mac.Sum(nil)))
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestReconcileSecret_CancelsProviderRead(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	cancelled := make(chan struct{})
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer vault.Close()
	provider := &providers.VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR": vault.URL, "VAULT_AUTH_METHOD": "token", "VAULT_TOKEN": "test-token",
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = provider.Close() }()
	driver := &SecretsDriver{
		provider: provider,
		secretTracker: map[string]*providers.SecretInfo{
			"mysql": {
				DockerSecretName: "mysql",
				SecretPath:       "secret/data/mysql",
				SecretField:      "value",
				LastHash:         fmt.Sprintf("%x", sha256.Sum256([]byte("old"))),
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- driver.ReconcileSecret(ctx, "mysql")
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("provider read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("reconciliation error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reconciliation ignored cancellation")
	}
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("provider HTTP request ignored cancellation")
	}
}

func TestReconcileSecret_ChecksAllMatchingSecrets(t *testing.T) {
	t.Parallel()
	for _, exactMatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("exact_match_%t", exactMatch), func(t *testing.T) {
			t.Parallel()
			reads := make(map[string]bool)
			provider := &reconciliationTestProvider{get: func(ctx context.Context, info *providers.SecretInfo) ([]byte, error) {
				reads[info.DockerSecretName] = true
				return []byte("unchanged"), nil
			}}
			driver := &SecretsDriver{provider: provider, secretTracker: make(map[string]*providers.SecretInfo)}
			for _, name := range []string{"username", "password", "unrelated"} {
				secretPath := "secret/data/database/mysql"
				if name == "unrelated" {
					secretPath = "secret/data/other"
				}
				driver.trackSecret(&providers.SecretInfo{DockerSecretName: name, SecretPath: secretPath}, []byte("unchanged"))
			}
			want := 2
			if exactMatch {
				driver.trackSecret(&providers.SecretInfo{DockerSecretName: "mysql", SecretPath: "secret/data/exact"}, []byte("unchanged"))
				want++
			}
			if err := driver.ReconcileSecret(context.Background(), "mysql"); err != nil {
				t.Fatal(err)
			}
			if len(reads) != want || reads["unrelated"] {
				t.Fatalf("reconciled %v, want all %d matching entries", reads, want)
			}
		})
	}
}

func TestReconcileSecret_PropagatesFailures(t *testing.T) {
	t.Parallel()
	for _, failOnRead := range []int{1, 2} {
		t.Run(fmt.Sprintf("read_%d", failOnRead), func(t *testing.T) {
			t.Parallel()
			failure := errors.New("provider unavailable")
			reads := 0
			provider := &reconciliationTestProvider{get: func(ctx context.Context, info *providers.SecretInfo) ([]byte, error) {
				reads++
				if reads == failOnRead {
					return nil, failure
				}
				return []byte("new"), nil
			}}
			driver := &SecretsDriver{provider: provider, secretTracker: make(map[string]*providers.SecretInfo)}
			driver.trackSecret(&providers.SecretInfo{DockerSecretName: "mysql"}, []byte("old"))
			if err := driver.ReconcileSecret(context.Background(), "mysql"); !errors.Is(err, failure) {
				t.Fatalf("reconciliation error = %v, want provider failure", err)
			}
		})
	}
}

type reconciliationTestProvider struct {
	get func(context.Context, *providers.SecretInfo) ([]byte, error)
}

func (p *reconciliationTestProvider) Initialize(map[string]string) error { return nil }
func (p *reconciliationTestProvider) GetSecret(ctx context.Context, info *providers.SecretInfo) ([]byte, error) {
	return p.get(ctx, info)
}
func (p *reconciliationTestProvider) SupportsRotation() bool                 { return true }
func (p *reconciliationTestProvider) GetSecretFieldLabel() string            { return "field" }
func (p *reconciliationTestProvider) BuildSecretPath(secrets.Request) string { return "" }
func (p *reconciliationTestProvider) GetProviderName() string                { return "test" }
func (p *reconciliationTestProvider) Close() error                           { return nil }

func TestUpdateDockerSecret_CleansUpAfterCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	removed := false
	client, err := dockerclient.NewClientWithOpts(
		dockerclient.WithHost("http://docker"),
		dockerclient.WithVersion("1.47"),
		dockerclient.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var body string
			switch {
			case strings.HasSuffix(req.URL.Path, "/secrets"):
				body = `[{"ID":"old-id","Spec":{"Name":"mysql"}}]`
			case strings.HasSuffix(req.URL.Path, "/secrets/create"):
				body = `{"ID":"new-id"}`
			case strings.HasSuffix(req.URL.Path, "/services"):
				cancel()
				return nil, ctx.Err()
			case strings.HasSuffix(req.URL.Path, "/secrets/new-id") && req.Method == http.MethodDelete:
				if err := req.Context().Err(); err != nil {
					return nil, err
				}
				removed = true
			default:
				t.Errorf("unexpected Docker request: %s %s", req.Method, req.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    req,
			}, nil
		})}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	driver := &SecretsDriver{dockerClient: client}
	if err := driver.updateDockerSecret(ctx, "mysql", []byte("new")); !errors.Is(err, context.Canceled) {
		t.Fatalf("rotation error = %v, want context.Canceled", err)
	}
	if !removed {
		t.Fatal("new secret was not removed after cancellation")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestBuildUpdatedSecretReferences(t *testing.T) {
	tests := []struct {
		name          string
		ref           *swarm.SecretReference
		oldSecretID   string
		newSecretName string
		wantUpdate    bool
		wantRef       *swarm.SecretReference
	}{
		{
			name: "updates exact name",
			ref: &swarm.SecretReference{
				SecretID:   "old-id",
				SecretName: "api",
			},
			oldSecretID:   "old-id",
			newSecretName: "api-123",
			wantUpdate:    true,
			wantRef: &swarm.SecretReference{
				SecretID:   "new-id",
				SecretName: "api-123",
			},
		},
		{
			name: "updates rotated name with matching ID",
			ref: &swarm.SecretReference{
				SecretID:   "old-id",
				SecretName: "api-1111111111111111111",
			},
			oldSecretID:   "old-id",
			newSecretName: "api-2222222222222222222",
			wantUpdate:    true,
			wantRef: &swarm.SecretReference{
				SecretID:   "new-id",
				SecretName: "api-2222222222222222222",
			},
		},
		{
			name: "preserves prefix collision",
			ref: &swarm.SecretReference{
				SecretID:   "prod-id",
				SecretName: "api-prod",
			},
			oldSecretID: "old-id",
		},
		{
			name: "does not match empty old ID",
			ref: &swarm.SecretReference{
				SecretName: "api-prod",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretRefs := []*swarm.SecretReference{tt.ref}
			updatedSecrets := make([]*swarm.SecretReference, len(secretRefs))

			needsUpdate := buildUpdatedSecretReferences(
				secretRefs,
				"api",
				tt.oldSecretID,
				tt.newSecretName,
				"new-id",
				updatedSecrets,
			)

			assertSecretReferenceUpdate(t, needsUpdate, tt.wantUpdate, updatedSecrets[0], tt.ref, tt.wantRef)
		})
	}
}

func assertSecretReferenceUpdate(
	t *testing.T,
	gotUpdate bool,
	wantUpdate bool,
	gotRef *swarm.SecretReference,
	originalRef *swarm.SecretReference,
	wantRef *swarm.SecretReference,
) {
	t.Helper()

	if gotUpdate != wantUpdate {
		t.Fatalf("needsUpdate = %v, want %v", gotUpdate, wantUpdate)
	}
	if !wantUpdate {
		assertSecretReferencePreserved(t, gotRef, originalRef)
		return
	}
	assertSecretReference(t, gotRef, wantRef)
}

func assertSecretReferencePreserved(t *testing.T, gotRef, originalRef *swarm.SecretReference) {
	t.Helper()

	if gotRef != originalRef {
		t.Fatal("expected unrelated secret reference to be preserved")
	}
}

func assertSecretReference(t *testing.T, gotRef, wantRef *swarm.SecretReference) {
	t.Helper()

	if gotRef.SecretID != wantRef.SecretID {
		t.Fatalf("SecretID = %q, want %q", gotRef.SecretID, wantRef.SecretID)
	}
	if gotRef.SecretName != wantRef.SecretName {
		t.Fatalf("SecretName = %q, want %q", gotRef.SecretName, wantRef.SecretName)
	}
}

func TestStopCancelsRotationBeforeClosingProvider(t *testing.T) {
	for _, phase := range []string{"reconciliation", "secret lookup"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			finished := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			closed := make(chan bool, 1)
			var calls atomic.Int32
			block := func(ctx context.Context) error {
				calls.Add(1)
				close(started)
				defer close(finished)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-release:
					return context.Canceled
				}
			}
			provider := &rotationLifecycleProvider{
				prepare: func(ctx context.Context) error {
					if phase == "reconciliation" {
						return block(ctx)
					}
					return nil
				},
				get: func(ctx context.Context) ([]byte, error) {
					if phase == "reconciliation" {
						return nil, context.Canceled
					}
					return nil, block(ctx)
				},
				close: func() error {
					select {
					case <-finished:
						closed <- true
					default:
						closed <- false
					}
					return nil
				},
			}
			driver := &SecretsDriver{
				provider:      provider,
				monitorCtx:    ctx,
				monitorCancel: cancel,
				secretTracker: map[string]*providers.SecretInfo{
					"test": {DockerSecretName: "test"},
				},
			}
			cycleDone := make(chan struct{})
			go func() {
				driver.checkForSecretChanges()
				close(cycleDone)
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("rotation did not start")
			}
			stopDone := make(chan error, 1)
			go func() { stopDone <- driver.Stop() }()
			select {
			case err := <-stopDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Stop did not cancel active rotation")
			}
			if !<-closed {
				t.Fatal("provider closed before rotation finished")
			}
			select {
			case <-cycleDone:
			case <-time.After(2 * time.Second):
				t.Fatal("rotation did not finish")
			}
			driver.checkForSecretChanges()
			if got := calls.Load(); got != 1 {
				t.Fatalf("rotation ran after Stop: calls = %d, want 1", got)
			}
		})
	}
}

type rotationLifecycleProvider struct {
	providers.SecretsProvider
	prepare func(context.Context) error
	get     func(context.Context) ([]byte, error)
	close   func() error
}

func (p *rotationLifecycleProvider) PrepareReconciliation(ctx context.Context, _ []*providers.SecretInfo) error {
	return p.prepare(ctx)
}

func (p *rotationLifecycleProvider) GetSecret(ctx context.Context, _ *providers.SecretInfo) ([]byte, error) {
	return p.get(ctx)
}

func (p *rotationLifecycleProvider) Close() error {
	return p.close()
}

func TestRepeatedGetDoesNotAcknowledgeUnappliedRotation(t *testing.T) {
	t.Parallel()
	var current atomic.Value
	current.Store("v1")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"PASSWORD": current.Load().(string)})
	}))
	t.Cleanup(server.Close)
	provider := &providers.DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.st.test",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "0s",
	}); err != nil {
		t.Fatal(err)
	}
	driver := &SecretsDriver{
		provider:      provider,
		config:        &SecretsConfig{EnableRotation: true},
		secretTracker: make(map[string]*providers.SecretInfo),
		monitorCtx:    t.Context(),
	}
	req := secrets.Request{
		SecretName:   "password",
		ServiceName:  "original-service",
		SecretLabels: map[string]string{"doppler_secret_name": "PASSWORD"},
	}
	if resp := driver.Get(req); resp.Err != "" || string(resp.Value) != "v1" {
		t.Fatalf("initial Get = %q, %q; want v1", resp.Value, resp.Err)
	}
	tracked := driver.secretTracker[req.SecretName]
	initialHash, initialUpdated := tracked.LastHash, tracked.LastUpdated

	// A reconnect/new consumer can fetch v2 while the original service still
	// mounts v1. Only a successful rotation may acknowledge that change.
	current.Store("v2")
	req.ServiceName = "new-service"
	req.SecretLabels["consumer"] = "new"
	if resp := driver.Get(req); resp.Err != "" || string(resp.Value) != "v2" {
		t.Fatalf("repeated Get = %q, %q; want v2", resp.Value, resp.Err)
	}
	changed, err := driver.hasSecretChanged(t.Context(), tracked)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("repeated Get hid a backend change before existing services rotated")
	}
	if tracked.LastHash != initialHash || !tracked.LastUpdated.Equal(initialUpdated) {
		t.Error("repeated Get acknowledged an unapplied rotation")
	}
	if !slices.Contains(tracked.ServiceNames, "original-service") ||
		!slices.Contains(tracked.ServiceNames, "new-service") || tracked.Labels["consumer"] != "new" {
		t.Fatalf("consumer metadata was not refreshed: services=%v, labels=%v", tracked.ServiceNames, tracked.Labels)
	}

	client, operations := newRotationDockerClient(t, req.SecretName)
	driver.dockerClient = client
	driver.checkForSecretChanges()
	for _, want := range []string{"create", "update", "remove"} {
		select {
		case got := <-operations:
			if got != want {
				t.Fatalf("Docker operation = %q, want %q", got, want)
			}
		default:
			t.Fatalf("rotation did not perform Docker operation %q", want)
		}
	}
	changed, err = driver.hasSecretChanged(t.Context(), tracked)
	if err != nil {
		t.Fatal(err)
	}
	if tracked.LastHash == initialHash || changed {
		t.Error("successful service rotation did not acknowledge v2")
	}
}

// Exercise the actual Docker client and rotation flow without a daemon.
func newRotationDockerClient(t *testing.T, secretName string) (*dockerclient.Client, <-chan string) {
	t.Helper()
	operations := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/v1.51")
		switch r.Method + " " + path {
		case "GET /secrets":
			_ = json.NewEncoder(w).Encode([]swarm.Secret{{
				ID: "old-id", Spec: swarm.SecretSpec{Annotations: swarm.Annotations{Name: secretName}},
			}})
		case "POST /secrets/create":
			var spec swarm.SecretSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				t.Error(err)
			}
			if string(spec.Data) != "v2" || !strings.HasPrefix(spec.Name, secretName+"-") {
				t.Errorf("created secret name/data = %q/%q; want versioned name/v2", spec.Name, spec.Data)
			}
			operations <- "create"
			_, _ = w.Write([]byte(`{"ID":"new-id"}`))
		case "GET /services":
			_ = json.NewEncoder(w).Encode([]swarm.Service{{
				ID: "service-id", Meta: swarm.Meta{Version: swarm.Version{Index: 1}},
				Spec: swarm.ServiceSpec{TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{
					Secrets: []*swarm.SecretReference{{
						SecretID:   "old-id",
						SecretName: secretName,
						File:       &swarm.SecretReferenceFileTarget{Name: "password"},
					}},
				}}},
			}})
		case "POST /services/service-id/update":
			var spec swarm.ServiceSpec
			if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
				t.Error(err)
			}
			if spec.TaskTemplate.ContainerSpec == nil || len(spec.TaskTemplate.ContainerSpec.Secrets) != 1 {
				t.Error("updated service lost its secret reference")
			} else {
				ref := spec.TaskTemplate.ContainerSpec.Secrets[0]
				if ref.SecretID != "new-id" || ref.File == nil || ref.File.Name != "password" {
					t.Errorf("updated secret reference = %+v; want new-id at password", ref)
				}
			}
			operations <- "update"
			_, _ = w.Write([]byte(`{}`))
		case "DELETE /secrets/old-id":
			operations <- "remove"
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected Docker API request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := dockerclient.NewClientWithOpts(dockerclient.WithHost(server.URL), dockerclient.WithVersion("1.51"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, operations
}
