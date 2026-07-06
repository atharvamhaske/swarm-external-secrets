package secrettransform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/sugar-org/swarm-external-secrets/internal/testutil/kumotest"
	"github.com/sugar-org/swarm-external-secrets/providers"
)

func TestKumoAWSKMSTransformerDecrypt(t *testing.T) {
	kumotest.Require(t)

	ctx := t.Context()
	plaintext := "kumo-kms-plaintext-v1"
	encryptionContext := map[string]string{
		"service": "swarm-external-secrets",
		"env":     "test",
	}

	ciphertextB64 := encryptWithKumoKMS(t, ctx, plaintext, encryptionContext)

	transformer := NewAWSKMSTransformer(kumotest.ProviderSettings())
	contextJSON, err := json.Marshal(encryptionContext)
	if err != nil {
		t.Fatalf("marshal encryption context: %v", err)
	}

	got, err := transformer.Transform(ctx, &providers.SecretInfo{
		Labels: map[string]string{
			"kms_decrypt":            "true",
			"kms_encryption_context": string(contextJSON),
		},
	}, []byte(ciphertextB64))
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("Transform = %q, want %q", got, plaintext)
	}
}

func TestKumoAWSKMSTransformerPassthroughWhenDisabled(t *testing.T) {
	kumotest.Require(t)

	transformer := NewAWSKMSTransformer(kumotest.ProviderSettings())
	value := []byte("leave-me-alone")

	got, err := transformer.Transform(t.Context(), &providers.SecretInfo{
		Labels: map[string]string{
			"kms_decrypt": "false",
		},
	}, value)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	if string(got) != string(value) {
		t.Fatalf("Transform = %q, want %q", got, value)
	}
}

func encryptWithKumoKMS(t *testing.T, ctx context.Context, plaintext string, encryptionContext map[string]string) string {
	t.Helper()

	client, err := kumotest.KMSClient(ctx)
	if err != nil {
		t.Fatalf("KMSClient: %v", err)
	}

	keyOut, err := client.CreateKey(ctx, &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	encryptOut, err := client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             keyOut.KeyMetadata.KeyId,
		Plaintext:         []byte(plaintext),
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return strings.TrimSpace(base64.StdEncoding.EncodeToString(encryptOut.CiphertextBlob))
}
