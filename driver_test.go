package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types/swarm"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sciops-org/swarm-external-secrets/providers"
)

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
	if !driver.hasSecretChanged(tracked) {
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
	if tracked.LastHash == initialHash || driver.hasSecretChanged(tracked) {
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
