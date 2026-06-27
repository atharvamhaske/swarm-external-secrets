package vaultcompat

import (
	"context"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
	openbaoapi "github.com/openbao/openbao/api/v2"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/login"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/vclient"
)

type Backend struct {
	client vclient.Client
	config Config
}

func New(cfg Config) (*Backend, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}

	if err := authenticate(client, cfg); err != nil {
		_ = client.Close()
		return nil, err
	}

	log.Printf("Successfully initialized %s provider using %s method", cfg.ProviderName, cfg.AuthMethod)
	return &Backend{client: client, config: cfg}, nil
}

func (b *Backend) GetSecret(ctx context.Context, secretInfo *utils.SecretInfo) ([]byte, error) {
	log.Debugf("Reading secret from %s path: %s", b.config.ProviderName, secretInfo.SecretPath)

	secret, err := b.client.Read(ctx, secretInfo.SecretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from %s: %w", b.config.ProviderName, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", secretInfo.SecretPath)
	}

	value, err := utils.ExtractSecretValueFromKV(secret.Data, secretInfo.SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %w", err)
	}

	log.Debugf("Successfully retrieved secret from %s", b.config.ProviderName)
	return value, nil
}

func (b *Backend) Close() error {
	if b.client == nil {
		return nil
	}
	return b.client.Close()
}

func newClient(cfg Config) (vclient.Client, error) {
	tlsCfg := vclient.TLSConfig{
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
		SkipVerify: cfg.SkipVerify,
	}

	switch cfg.ProviderName {
	case "openbao":
		apiConfig := openbaoapi.DefaultConfig()
		apiConfig.Address = cfg.Address
		if err := vclient.ConfigureOpenBaoTLS(apiConfig, tlsCfg); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}

		client, err := openbaoapi.NewClient(apiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create openbao client: %w", err)
		}

		return vclient.NewOpenBao(client), nil
	default:
		apiConfig := vaultapi.DefaultConfig()
		apiConfig.Address = cfg.Address
		if err := vclient.ConfigureHashiVaultTLS(apiConfig, tlsCfg); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}

		client, err := vaultapi.NewClient(apiConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create vault client: %w", err)
		}

		return vclient.NewHashiVault(client), nil
	}
}

func authenticate(client vclient.Client, cfg Config) error {
	loginCfg, err := cfg.loginConfig()
	if err != nil {
		return err
	}

	method, err := login.New(login.Config{
		Method:          loginCfg.Method,
		Token:           loginCfg.Token,
		RoleID:          loginCfg.RoleID,
		SecretID:        loginCfg.SecretID,
		AppRoleAuthPath: loginCfg.AppRoleAuthPath,
		JWTRole:         loginCfg.JWTRole,
		JWTAuthPath:     loginCfg.JWTAuthPath,
		JWTSource:       loginCfg.JWTSource,
	})
	if err != nil {
		return err
	}

	result, err := method.Login(context.Background(), client)
	if err != nil {
		switch cfg.AuthMethod {
		case "approle":
			return fmt.Errorf("approle authentication failed: %w", err)
		case "jwt":
			return fmt.Errorf("jwt authentication failed: %w", err)
		default:
			return err
		}
	}

	if result == nil || result.ClientToken == "" {
		switch cfg.AuthMethod {
		case "approle":
			return fmt.Errorf("no auth info returned from approle login")
		case "jwt":
			return fmt.Errorf("no auth info returned from jwt login")
		default:
			return fmt.Errorf("authentication returned no client token")
		}
	}

	client.SetToken(result.ClientToken)
	return nil
}
