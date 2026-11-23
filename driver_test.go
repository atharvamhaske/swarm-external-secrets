package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
