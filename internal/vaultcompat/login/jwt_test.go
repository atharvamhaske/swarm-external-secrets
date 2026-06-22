package login

import (
	"context"
	"testing"

	"github.com/sugar-org/vault-swarm-plugin/internal/vaultcompat/jwtsource"
	"github.com/sugar-org/vault-swarm-plugin/internal/vaultcompat/vclient"
)

type mockClient struct {
	write func(ctx context.Context, path string, data map[string]any) (*vclient.Secret, error)
}

func (m mockClient) Read(context.Context, string) (*vclient.Secret, error) { return nil, nil }

func (m mockClient) Write(ctx context.Context, path string, data map[string]any) (*vclient.Secret, error) {
	return m.write(ctx, path, data)
}

func (m mockClient) SetToken(string) {}

func (m mockClient) Close() error { return nil }

func TestJWT_Login(t *testing.T) {
	var gotPath string
	var gotRole string
	var gotJWT string

	client := mockClient{write: func(_ context.Context, path string, data map[string]any) (*vclient.Secret, error) {
		gotPath = path
		gotRole, _ = data["role"].(string)
		gotJWT, _ = data["jwt"].(string)

		return &vclient.Secret{
			Auth: &vclient.Auth{ClientToken: "vault-token"},
		}, nil
	}}

	method := JWT{
		Path:   "jwt",
		Role:   "swarm-external-secrets",
		Source: jwtsource.Static{Value: "test.jwt.token"},
	}

	result, err := method.Login(context.Background(), client)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if result.ClientToken != "vault-token" {
		t.Fatalf("ClientToken = %q, want vault-token", result.ClientToken)
	}
	if gotPath != "auth/jwt/login" {
		t.Fatalf("login path = %q, want auth/jwt/login", gotPath)
	}
	if gotRole != "swarm-external-secrets" {
		t.Fatalf("login role = %q, want swarm-external-secrets", gotRole)
	}
	if gotJWT != "test.jwt.token" {
		t.Fatalf("login jwt = %q, want test.jwt.token", gotJWT)
	}
}

func TestJWT_Login_CustomAuthPath(t *testing.T) {
	var gotPath string

	client := mockClient{write: func(_ context.Context, path string, _ map[string]any) (*vclient.Secret, error) {
		gotPath = path
		return &vclient.Secret{Auth: &vclient.Auth{ClientToken: "vault-token"}}, nil
	}}

	method := JWT{
		Path:   "/oidc/",
		Role:   "swarm-external-secrets",
		Source: jwtsource.Static{Value: "test.jwt.token"},
	}

	if _, err := method.Login(context.Background(), client); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if gotPath != "auth/oidc/login" {
		t.Fatalf("login path = %q, want auth/oidc/login", gotPath)
	}
}

func TestJWT_Login_MissingRole(t *testing.T) {
	method := JWT{Source: jwtsource.Static{Value: "token"}}

	_, err := method.Login(context.Background(), mockClient{})
	if err == nil || err.Error() != "jwt role is required" {
		t.Fatalf("Login() error = %v", err)
	}
}

func TestJWT_Login_NoClientToken(t *testing.T) {
	client := mockClient{write: func(context.Context, string, map[string]any) (*vclient.Secret, error) {
		return &vclient.Secret{}, nil
	}}

	method := JWT{
		Role:   "swarm-external-secrets",
		Source: jwtsource.Static{Value: "test.jwt.token"},
	}

	_, err := method.Login(context.Background(), client)
	if err == nil || err.Error() != "jwt login returned no client token" {
		t.Fatalf("Login() error = %v", err)
	}
}

func TestJWT_Login_SourceError(t *testing.T) {
	method := JWT{
		Role:   "swarm-external-secrets",
		Source: jwtsource.Static{Value: ""},
	}

	_, err := method.Login(context.Background(), mockClient{})
	if err == nil || err.Error() != "jwt value is empty" {
		t.Fatalf("Login() error = %v", err)
	}
}
