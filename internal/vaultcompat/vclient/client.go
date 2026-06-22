package vclient

import (
	"context"

	vaultapi "github.com/hashicorp/vault/api"
	openbaoapi "github.com/openbao/openbao/api/v2"
)

type Client interface {
	Read(ctx context.Context, path string) (*Secret, error)
	Write(ctx context.Context, path string, data map[string]any) (*Secret, error)
	SetToken(token string)
	Close() error
}

type Secret struct {
	Data map[string]interface{}
	Auth *Auth
}

type Auth struct {
	ClientToken string
	Renewable   bool
	LeaseTTL    int
}

type TLSConfig struct {
	CACert     string
	ClientCert string
	ClientKey  string
	SkipVerify bool
}

func ConfigureHashiVaultTLS(config *vaultapi.Config, tlsCfg TLSConfig) error {
	return config.ConfigureTLS(&vaultapi.TLSConfig{
		CACert:     tlsCfg.CACert,
		ClientCert: tlsCfg.ClientCert,
		ClientKey:  tlsCfg.ClientKey,
		Insecure:   tlsCfg.SkipVerify,
	})
}

func ConfigureOpenBaoTLS(config *openbaoapi.Config, tlsCfg TLSConfig) error {
	return config.ConfigureTLS(&openbaoapi.TLSConfig{
		CACert:     tlsCfg.CACert,
		ClientCert: tlsCfg.ClientCert,
		ClientKey:  tlsCfg.ClientKey,
		Insecure:   tlsCfg.SkipVerify,
	})
}
