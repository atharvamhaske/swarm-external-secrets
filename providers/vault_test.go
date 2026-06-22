package providers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
)

func TestVaultProvider_AuthenticateWithJWT(t *testing.T) {
	var loginRequest struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			if r.Method != http.MethodPut {
				t.Fatalf("jwt login method = %s, want PUT", r.Method)
			}

			if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
				t.Fatalf("decode jwt login request: %v", err)
			}

			_, _ = w.Write([]byte(`{"auth":{"client_token":"vault-client-token"}}`))
		case "/v1/secret/data/database/mysql":
			if got := r.Header.Get("X-Vault-Token"); got != "vault-client-token" {
				t.Fatalf("X-Vault-Token = %q, want vault-client-token", got)
			}

			_, _ = w.Write([]byte(`{"data":{"data":{"password":"jwt-secret"}}}`))
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	provider := &VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR":        server.URL,
		"VAULT_AUTH_METHOD": "jwt",
		"VAULT_JWT_ROLE":    "swarm-external-secrets",
		"VAULT_JWT":         "test.jwt.token",
		"VAULT_MOUNT_PATH":  "secret",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	got, err := provider.GetSecret(t.Context(), secrets.Request{
		SecretName: "fallback",
		SecretLabels: map[string]string{
			"vault_path":  "database/mysql",
			"vault_field": "password",
		},
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}

	if string(got) != "jwt-secret" {
		t.Fatalf("GetSecret() = %q, want jwt-secret", string(got))
	}

	if loginRequest.Role != "swarm-external-secrets" {
		t.Fatalf("login role = %q, want swarm-external-secrets", loginRequest.Role)
	}

	if loginRequest.JWT != "test.jwt.token" {
		t.Fatalf("login jwt = %q, want test.jwt.token", loginRequest.JWT)
	}
}

func TestVaultProvider_AuthenticateWithJWT_CustomAuthPathAndFilePrecedence(t *testing.T) {
	var loginRequest struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/oidc/login" {
			t.Fatalf("jwt login path = %s, want /v1/auth/oidc/login", r.URL.Path)
		}

		if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
			t.Fatalf("decode jwt login request: %v", err)
		}

		_, _ = w.Write([]byte(`{"auth":{"client_token":"vault-client-token"}}`))
	}))
	defer server.Close()

	jwtFile := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(jwtFile, []byte("file.jwt.token\n"), 0o600); err != nil {
		t.Fatalf("write jwt file: %v", err)
	}

	provider := &VaultProvider{}
	if err := provider.Initialize(map[string]string{
		"VAULT_ADDR":          server.URL,
		"VAULT_AUTH_METHOD":   "jwt",
		"VAULT_JWT_ROLE":      "swarm-external-secrets",
		"VAULT_JWT":           "env.jwt.token",
		"VAULT_JWT_FILE":      jwtFile,
		"VAULT_JWT_AUTH_PATH": "/oidc/",
	}); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	defer func() { _ = provider.Close() }()

	if loginRequest.JWT != "file.jwt.token" {
		t.Fatalf("login jwt = %q, want file.jwt.token", loginRequest.JWT)
	}
}

func TestVaultProvider_AuthenticateWithJWT_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name: "missing role",
			config: map[string]string{
				"VAULT_AUTH_METHOD": "jwt",
				"VAULT_JWT":         "test.jwt.token",
			},
			wantErr: "VAULT_JWT_ROLE is required for jwt authentication",
		},
		{
			name: "missing jwt",
			config: map[string]string{
				"VAULT_AUTH_METHOD": "jwt",
				"VAULT_JWT_ROLE":    "swarm-external-secrets",
			},
			wantErr: "VAULT_JWT or VAULT_JWT_FILE is required for jwt authentication",
		},
		{
			name: "empty jwt file",
			config: map[string]string{
				"VAULT_AUTH_METHOD": "jwt",
				"VAULT_JWT_ROLE":    "swarm-external-secrets",
				"VAULT_JWT_FILE":    emptyFile(t),
			},
			wantErr: "VAULT_JWT_FILE is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &VaultProvider{}
			err := provider.Initialize(tt.config)
			if err == nil {
				t.Fatal("Initialize() error = nil, want error")
			}

			if got := err.Error(); got != "failed to authenticate with vault: "+tt.wantErr {
				t.Fatalf("Initialize() error = %q, want %q", got, "failed to authenticate with vault: "+tt.wantErr)
			}
		})
	}
}

func TestVaultProvider_AuthenticateWithJWT_LoginFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/jwt/login" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}

		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	defer server.Close()

	provider := &VaultProvider{}
	err := provider.Initialize(map[string]string{
		"VAULT_ADDR":        server.URL,
		"VAULT_AUTH_METHOD": "jwt",
		"VAULT_JWT_ROLE":    "swarm-external-secrets",
		"VAULT_JWT":         "test.jwt.token",
	})
	if err == nil {
		t.Fatal("Initialize() error = nil, want error")
	}

	if got := err.Error(); got != "failed to authenticate with vault: jwt authentication failed: Error making API request.\n\nURL: PUT "+server.URL+"/v1/auth/jwt/login\nCode: 403. Errors:\n\n* permission denied" {
		if !containsAll(got, "failed to authenticate with vault", "jwt authentication failed", "403", "permission denied") {
			t.Fatalf("Initialize() error = %q", got)
		}
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}

func emptyFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "empty-jwt")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty jwt file: %v", err)
	}

	return path
}
