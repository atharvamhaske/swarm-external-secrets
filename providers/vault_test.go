package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
)

func TestVaultJWTInitializeAndReadSecret(t *testing.T) {
	const (
		expectedJWT        = "header.payload.signature"
		expectedRole       = "swarm-plugin"
		expectedVaultToken = "vault-client-token"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			if r.Method != http.MethodPut && r.Method != http.MethodPost {
				t.Fatalf("unexpected login method: %s", r.Method)
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode login payload: %v", err)
			}
			if got := payload["role"]; got != expectedRole {
				t.Fatalf("unexpected role: %s", got)
			}
			if got := payload["jwt"]; got != expectedJWT {
				t.Fatalf("unexpected jwt: %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth":{"client_token":"` + expectedVaultToken + `"}}`))
		case "/v1/secret/data/database/mysql":
			if got := r.Header.Get("X-Vault-Token"); got != expectedVaultToken {
				t.Fatalf("unexpected vault token: %s", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"data":{"password":"vault-jwt-pass-v1"}}}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	jwtFile, err := os.CreateTemp(t.TempDir(), "vault-jwt-*")
	if err != nil {
		t.Fatalf("create temp jwt file: %v", err)
	}
	if _, err := jwtFile.WriteString(expectedJWT + "\n"); err != nil {
		t.Fatalf("write temp jwt file: %v", err)
	}
	if err := jwtFile.Close(); err != nil {
		t.Fatalf("close temp jwt file: %v", err)
	}

	provider := &VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR":        server.URL,
		"VAULT_AUTH_METHOD": "jwt",
		"VAULT_JWT_FILE":    jwtFile.Name(),
		"VAULT_JWT_ROLE":    expectedRole,
		"VAULT_MOUNT_PATH":  "secret",
	}); err != nil {
		t.Fatalf("initialize provider: %v", err)
	}

	value, err := provider.GetSecret(context.Background(), secrets.Request{
		ServiceName: "database",
		SecretName:  "mysql",
		SecretLabels: map[string]string{
			"vault_field": "password",
		},
	})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}

	if got := string(value); got != "vault-jwt-pass-v1" {
		t.Fatalf("unexpected secret value: %s", got)
	}
}

func TestVaultJWTRequiresRole(t *testing.T) {
	provider := &VaultProvider{
		config: &SecretsConfig{
			AuthMethod: "jwt",
			JWT:        "header.payload.signature",
		},
	}

	if err := provider.authenticate(); err == nil || err.Error() != "VAULT_JWT_ROLE is required for jwt authentication" {
		t.Fatalf("expected missing role error, got %v", err)
	}
}

func TestVaultJWTLoginPathUsesCustomMount(t *testing.T) {
	provider := &VaultProvider{
		config: &SecretsConfig{
			JWTAuthPath: "/custom-jwt/",
		},
	}

	if got := provider.vaultJWTLoginPath(); got != "auth/custom-jwt/login" {
		t.Fatalf("unexpected login path: %s", got)
	}
}
