---
title: HashiCorp Vault
type: docs
weight: 11
---

HashiCorp Vault is the default provider. It supports token and AppRole authentication, KV-style secret lookup, field extraction, and rotation checks.

## Environment Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SECRETS_PROVIDER` | no | `vault` | Selects the provider |
| `VAULT_ADDR` | yes | none | Vault server address |
| `VAULT_AUTH_METHOD` | no | `token` | Supported values: `token`, `approle` |
| `VAULT_TOKEN` | for token auth | none | Required when using token auth |
| `VAULT_ROLE_ID` | for approle auth | none | Required when using AppRole |
| `VAULT_SECRET_ID` | for approle auth | none | Required when using AppRole |
| `VAULT_MOUNT_PATH` | no | `secret` | KV mount path |
| `VAULT_SKIP_VERIFY` | no | `false` | Skips TLS certificate verification |
| `VAULT_CACERT` | optional | none | Custom CA bundle path |
| `VAULT_CLIENT_CERT` | optional | none | Client certificate path for mTLS |
| `VAULT_CLIENT_KEY` | optional | none | Client key path for mTLS |

## Basic Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_TOKEN="hvs.example-token"
```

## AppRole Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_AUTH_METHOD="approle" \
    VAULT_ROLE_ID="<role-id>" \
    VAULT_SECRET_ID="<secret-id>"
```

## Secret Labels

- `vault_path`
- `vault_field`

## Path Resolution

If `vault_path` is set, the plugin reads that path directly.

When `VAULT_MOUNT_PATH="secret"`, the provider automatically uses KV v2 style paths:

- `vault_path: "demo/app"` becomes `secret/data/demo/app`
- default service-scoped lookup becomes `secret/data/<service>/<secret>`

For non-`secret` mount paths, it uses the mount path without the automatic `/data/` segment.

## Field Extraction

If `vault_field` is set, that exact field is returned.

If no field is set, the provider tries common keys in this order:

- `value`
- `password`
- `secret`
- `data`

If none of those exist, it falls back to the first string value in the secret payload.

## Docker Compose Example

```yaml
secrets:
  app_password:
    driver: swarm-external-secrets:latest
    labels:
      vault_path: "demo/app"
      vault_field: "password"
```

## Authentication

- Token authentication via `VAULT_TOKEN`
- AppRole authentication via `VAULT_ROLE_ID` and `VAULT_SECRET_ID`
- TLS configuration through CA bundle, client cert, client key, and optional skip-verify

## Rotation Notes

Vault supports rotation checks. The provider hashes the extracted value and compares it during polling, so field selection should stay stable across updates.

- Token
- AppRole
