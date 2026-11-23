package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// runSharedBase64DecodeCases checks the same opt-in decoding contract for Vault
// and OpenBao while leaving provider-specific initialization to the caller.
func runSharedBase64DecodeCases(t *testing.T, initProvider func(serverURL string) SecretsProvider) {
	t.Helper()

	binaryPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02}
	encodedPayload := base64.StdEncoding.EncodeToString(binaryPayload)
	const invalidPayload = "sensitive-invalid-base64!"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/app/binary":
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"keystore":"%s"}}}`, encodedPayload)
		case "/v1/secret/data/app/invalid":
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"keystore":"%s"}}}`, invalidPayload)
		case "/v1/secret/data/app/missing":
			http.NotFound(w, r)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := initProvider(server.URL)
	defer func() { _ = provider.Close() }()

	tests := []struct {
		name          string
		path          string
		labels        map[string]string
		cancelContext bool
		want          []byte
		wantErr       bool
	}{
		{name: "decoded", path: "binary", labels: map[string]string{"base64_decode": "true"}, want: binaryPayload},
		{name: "unchanged", path: "binary", want: []byte(encodedPayload)},
		{name: "disabled accepts invalid base64", path: "invalid", labels: map[string]string{"base64_decode": "false"}, want: []byte(invalidPayload)},
		{name: "enabled rejects invalid base64", path: "invalid", labels: map[string]string{"base64_decode": "true"}, wantErr: true},
		{name: "backend error", path: "missing", labels: map[string]string{"base64_decode": "true"}, wantErr: true},
		{name: "canceled context", path: "binary", labels: map[string]string{"base64_decode": "true"}, cancelContext: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &SecretInfo{
				DockerSecretName: "test-keystore",
				SecretPath:       "secret/data/app/" + tt.path,
				SecretField:      "keystore",
				Labels:           tt.labels,
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelContext {
				cancel()
			}
			got, err := provider.GetSecret(ctx, info)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.cancelContext && !errors.Is(err, context.Canceled) {
				t.Fatalf("GetSecret() error = %v, want context.Canceled", err)
			}
			if tt.wantErr && got != nil {
				t.Fatalf("GetSecret() returned data on error: %v", got)
			}
			if err != nil && strings.Contains(err.Error(), invalidPayload) {
				t.Fatalf("GetSecret() error leaked the secret value: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("GetSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}
