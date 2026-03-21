---
title: OpenBao
type: docs
weight: 14
---

OpenBao is implemented with Vault-compatible behavior, so its configuration and lookup rules closely match the Vault provider.

## Environment Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SECRETS_PROVIDER` | no | `openbao` | Selects the provider |
| `OPENBAO_ADDR` | no | `http://localhost:8200` | OpenBao server address |
| `OPENBAO_AUTH_METHOD` | no | `token` | Supported values: `token`, `approle` |
| `OPENBAO_TOKEN` | for token auth | none | Required when using token auth |
| `OPENBAO_ROLE_ID` | for approle auth | none | Required when using AppRole |
| `OPENBAO_SECRET_ID` | for approle auth | none | Required when using AppRole |
| `OPENBAO_MOUNT_PATH` | no | `secret` | KV mount path |
| `OPENBAO_SKIP_VERIFY` | no | `false` | Skips TLS certificate verification |
| `OPENBAO_CACERT` | optional | none | Custom CA bundle path |
| `OPENBAO_CLIENT_CERT` | optional | none | Client certificate path for mTLS |
| `OPENBAO_CLIENT_KEY` | optional | none | Client key path for mTLS |

## Basic Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="https://openbao.example.com:8200" \
    OPENBAO_TOKEN="<token>"
```

## AppRole Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="https://openbao.example.com:8200" \
    OPENBAO_AUTH_METHOD="approle" \
    OPENBAO_ROLE_ID="<role-id>" \
    OPENBAO_SECRET_ID="<secret-id>"
```

## Secret Labels

- `openbao_path`
- `openbao_field`

## Path Resolution

If `openbao_path` is set, the provider reads that path directly.

When `OPENBAO_MOUNT_PATH="secret"`, the provider automatically uses KV v2 style paths:

- `openbao_path: "demo/app"` becomes `secret/data/demo/app`
- default service-scoped lookup becomes `secret/data/<service>/<secret>`

For non-`secret` mount paths, the provider uses the configured mount path directly.

## Field Extraction

If `openbao_field` is set, that exact field is returned.

If no field is set, the provider tries:

- `value`
- `password`
- `secret`
- `data`

If none of those exist, it falls back to the first string value in the secret payload.

## Docker Compose Example

```yaml
secrets:
  app_secret:
    driver: swarm-external-secrets:latest
    labels:
      openbao_path: "app/config"
      openbao_field: "secret_key"
```

## Rotation Notes

OpenBao supports rotation checks in the same way as Vault by hashing the extracted value on each poll.
