package providers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/sugar-org/swarm-external-secrets/internal/testutil/kumotest"
)

func TestKumoAWSProviderInitializeAndGetSecret(t *testing.T) {
	kumotest.Require(t)

	ctx := t.Context()
	secretName := uniqueSecretName(t, "initialize-get")
	secretField := "password"
	secretValue := "kumo-plaintext-v1"

	createKumoSecret(t, ctx, secretName, map[string]string{
		secretField: secretValue,
	})

	provider := newKumoAWSProvider(t)

	value, err := provider.GetSecret(ctx, &SecretInfo{
		SecretPath:  secretName,
		SecretField: secretField,
	})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != secretValue {
		t.Fatalf("GetSecret = %q, want %q", value, secretValue)
	}
}

func TestKumoAWSProviderFieldExtraction(t *testing.T) {
	kumotest.Require(t)

	ctx := t.Context()
	secretName := uniqueSecretName(t, "field-extract")
	secretField := "api_key"
	secretValue := "kumo-field-value"

	createKumoSecret(t, ctx, secretName, map[string]string{
		secretField: secretValue,
		"other":     "ignored",
	})

	provider := newKumoAWSProvider(t)

	value, err := provider.GetSecret(ctx, &SecretInfo{
		SecretPath:  secretName,
		SecretField: secretField,
	})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(value) != secretValue {
		t.Fatalf("GetSecret = %q, want %q", value, secretValue)
	}
}

func TestKumoAWSProviderRotationHashDetection(t *testing.T) {
	kumotest.Require(t)

	ctx := t.Context()
	secretName := uniqueSecretName(t, "rotation-hash")
	secretField := "password"
	initialValue := "kumo-rotate-v1"
	rotatedValue := "kumo-rotate-v2"

	createKumoSecret(t, ctx, secretName, map[string]string{
		secretField: initialValue,
	})

	provider := newKumoAWSProvider(t)
	secretInfo := &SecretInfo{
		SecretPath:  secretName,
		SecretField: secretField,
		LastHash:    sha256Hex([]byte(initialValue)),
	}

	value, err := provider.GetSecret(ctx, secretInfo)
	if err != nil {
		t.Fatalf("GetSecret initial: %v", err)
	}
	if sha256Hex(value) != secretInfo.LastHash {
		t.Fatal("expected hash to match stored value before rotation")
	}

	putKumoSecretValue(t, ctx, secretName, map[string]string{
		secretField: rotatedValue,
	})

	value, err = provider.GetSecret(ctx, secretInfo)
	if err != nil {
		t.Fatalf("GetSecret after rotation: %v", err)
	}
	if sha256Hex(value) == secretInfo.LastHash {
		t.Fatal("expected hash to change after PutSecretValue")
	}
	if string(value) != rotatedValue {
		t.Fatalf("GetSecret = %q, want %q", value, rotatedValue)
	}
}

func newKumoAWSProvider(t *testing.T) *AWSProvider {
	t.Helper()

	provider := &AWSProvider{}
	if err := provider.Initialize(kumotest.ProviderSettings()); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return provider
}

func createKumoSecret(t *testing.T, ctx context.Context, name string, fields map[string]string) {
	t.Helper()

	client, err := kumotest.SecretsManagerClient(ctx)
	if err != nil {
		t.Fatalf("SecretsManagerClient: %v", err)
	}

	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal secret payload: %v", err)
	}

	_, err = client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(string(payload)),
	})
	if err != nil {
		t.Fatalf("CreateSecret(%q): %v", name, err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_, _ = client.DeleteSecret(cleanupCtx, &secretsmanager.DeleteSecretInput{
			SecretId:                   aws.String(name),
			ForceDeleteWithoutRecovery: aws.Bool(true),
		})
	})
}

func putKumoSecretValue(t *testing.T, ctx context.Context, name string, fields map[string]string) {
	t.Helper()

	client, err := kumotest.SecretsManagerClient(ctx)
	if err != nil {
		t.Fatalf("SecretsManagerClient: %v", err)
	}

	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal secret payload: %v", err)
	}

	_, err = client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(name),
		SecretString: aws.String(string(payload)),
	})
	if err != nil {
		t.Fatalf("PutSecretValue(%q): %v", name, err)
	}
}

func uniqueSecretName(t *testing.T, suffix string) string {
	t.Helper()
	return fmt.Sprintf("kumo-test/%s/%s", suffix, strings.ReplaceAll(t.Name(), "/", "-"))
}

func sha256Hex(value []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(value))
}
