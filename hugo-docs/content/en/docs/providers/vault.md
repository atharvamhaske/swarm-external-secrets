---
title: HashiCorp Vault
type: docs
weight: 11
---

HashiCorp Vault is the default provider. It supports token, AppRole, and JWT authentication, KV-style secret lookup, field extraction, and rotation checks.

## Environment Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SECRETS_PROVIDER` | no | `vault` | Selects the provider |
| `VAULT_ADDR` | yes | none | Vault server address |
| `VAULT_AUTH_METHOD` | no | `token` | Supported values: `token`, `approle`, `jwt` |
| `VAULT_TOKEN` | for token auth | none | Required when using token auth |
| `VAULT_ROLE_ID` | for approle auth | none | Required when using AppRole |
| `VAULT_SECRET_ID` | for approle auth | none | Required when using AppRole |
| `VAULT_JWT` | for jwt auth | none | Raw JWT presented to Vault |
| `VAULT_JWT_FILE` | for jwt auth | none | Path to a JWT file; useful for non-interactive workloads |
| `VAULT_JWT_ROLE` | for jwt auth | none | Vault JWT role name |
| `VAULT_JWT_AUTH_PATH` | no | `jwt` | Auth mount used for JWT login |
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

## JWT Configuration

This JWT path is intended for non-interactive plugin logins. Vault must already have the JWT auth method enabled and configured with `jwks_url`, `oidc_discovery_url`, or another supported verifier, and the target role must be a `role_type="jwt"` role with the expected `bound_audiences`.

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_AUTH_METHOD="jwt" \
    VAULT_JWT_FILE="/run/swarm-external-secrets/vault-jwt" \
    VAULT_JWT_ROLE="swarm-plugin" \
    VAULT_JWT_AUTH_PATH="jwt"
```

You can also pass a raw JWT directly through `VAULT_JWT`, but the file-based form is a better fit for workload identity systems that refresh tokens on disk.

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
- JWT authentication via `VAULT_JWT` or `VAULT_JWT_FILE` and `VAULT_JWT_ROLE`
- TLS configuration through CA bundle, client cert, client key, and optional skip-verify

## Rotation Notes

Vault supports rotation checks. The provider hashes the extracted value and compares it during polling, so field selection should stay stable across updates.
