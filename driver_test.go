package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types/swarm"

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
