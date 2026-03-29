package providers

import "testing"

func TestAWSResolveAuthMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     AWSConfig
		want    string
		wantErr bool
	}{
		{
			name: "web identity token file",
			cfg: AWSConfig{
				RoleARN:              "arn:aws:iam::123456789012:role/swarm-secrets",
				WebIdentityTokenFile: "/run/swarm-external-secrets/aws-web-identity-token",
			},
			want: "web-identity-token-file",
		},
		{
			name: "direct SPIFFE web identity",
			cfg: AWSConfig{
				RoleARN:           "arn:aws:iam::123456789012:role/swarm-secrets",
				SpiffeJWTAudience: "awssm",
			},
			want: "spiffe-workload-api-web-identity",
		},
		{
			name: "static credentials",
			cfg: AWSConfig{
				AccessKey: "test",
				SecretKey: "secret",
			},
			want: "static-credentials",
		},
		{
			name: "profile",
			cfg: AWSConfig{
				Profile: "default",
			},
			want: "shared-profile",
		},
		{
			name: "default chain",
			cfg:  AWSConfig{},
			want: "default-credential-chain",
		},
		{
			name: "partial static credentials",
			cfg: AWSConfig{
				AccessKey: "test",
			},
			wantErr: true,
		},
		{
			name: "partial web identity",
			cfg: AWSConfig{
				RoleARN: "arn:aws:iam::123456789012:role/swarm-secrets",
			},
			wantErr: true,
		},
		{
			name: "partial direct SPIFFE web identity",
			cfg: AWSConfig{
				SpiffeJWTAudience: "awssm",
			},
			wantErr: true,
		},
		{
			name: "conflicting auth modes",
			cfg: AWSConfig{
				AccessKey:            "test",
				SecretKey:            "secret",
				RoleARN:              "arn:aws:iam::123456789012:role/swarm-secrets",
				WebIdentityTokenFile: "/run/swarm-external-secrets/aws-web-identity-token",
			},
			wantErr: true,
		},
		{
			name: "conflicting token file and direct SPIFFE modes",
			cfg: AWSConfig{
				RoleARN:              "arn:aws:iam::123456789012:role/swarm-secrets",
				WebIdentityTokenFile: "/run/swarm-external-secrets/aws-web-identity-token",
				SpiffeJWTAudience:    "awssm",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &AWSProvider{config: &tt.cfg}
			got, err := provider.resolveAuthMode()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode %q", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Fatalf("expected mode %q, got %q", tt.want, got)
			}
		})
	}
}
