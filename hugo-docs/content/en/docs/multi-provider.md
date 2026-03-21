---
title: Multi-Provider Configuration
linkTitle: Multi-Provider
type: docs
description: Complete configuration reference for all supported secret providers
weight: 5
---

The Vault Swarm Plugin supports multiple secrets providers, allowing you to use different backends for secret management while maintaining the same Docker Swarm secrets interface.

## Supported Providers

### 1. HashiCorp Vault (default)

**Provider Type:** `vault`

| Variable | Description | Default |
|---|---|---|
| `VAULT_ADDR` | Vault server address | `http://localhost:8200` |
| `VAULT_TOKEN` | Vault token for authentication | — |
| `VAULT_MOUNT_PATH` | Mount path for KV engine | `secret` |
| `VAULT_AUTH_METHOD` | Authentication method (`token`, `approle`) | `token` |
| `VAULT_ROLE_ID` | Role ID for AppRole authentication | — |
| `VAULT_SECRET_ID` | Secret ID for AppRole authentication | — |
| `VAULT_SKIP_VERIFY` | Skip TLS verification | `false` |

### 2. AWS Secrets Manager

**Provider Type:** `aws`

| Variable | Description | Default |
|---|---|---|
| `AWS_REGION` | AWS region | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS access key | — |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | — |
| `AWS_PROFILE` | AWS profile name | — |

### 3. Azure Key Vault

**Provider Type:** `azure`

| Variable | Description |
|---|---|
| `AZURE_VAULT_URL` | Key Vault URL |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_CLIENT_ID` | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Service principal secret |
| `AZURE_ACCESS_TOKEN` | Direct access token |

### 4. OpenBao

**Provider Type:** `openbao`

| Variable | Description | Default |
|---|---|---|
| `OPENBAO_ADDR` | OpenBao server address | `http://localhost:8200` |
| `OPENBAO_TOKEN` | OpenBao token | — |
| `OPENBAO_MOUNT_PATH` | Mount path | `secret` |
| `OPENBAO_AUTH_METHOD` | Authentication method | `token` |
| `OPENBAO_ROLE_ID` | Role ID | — |
| `OPENBAO_SECRET_ID` | Secret ID | — |
| `OPENBAO_SKIP_VERIFY` | Skip TLS verification | `false` |

### 5. GCP Secret Manager (Placeholder)

**Provider Type:** `gcp`

> Currently a placeholder implementation. Use other providers for production.

## Docker Compose Examples

### Vault Provider

```yaml
secrets:
  mysql_password:
    driver: swarm-external-secrets:latest
    labels:
      vault_path: "database/mysql"
      vault_field: "password"
```

### AWS Secrets Manager

```yaml
secrets:
  api_key:
    driver: swarm-external-secrets:latest
    labels:
      aws_secret_name: "prod/api/key"
      aws_field: "api_key"
```

### Azure Key Vault

```yaml
secrets:
  database_connection:
    driver: swarm-external-secrets:latest
    labels:
      azure_secret_name: "database-connection-string"
      azure_field: "connection_string"
```

## Multiple Providers in the Same Swarm Cluster

For production isolation, run one provider per plugin instance (unique plugin name) and reference each instance as a separate secret driver.

### Example: Vault + OpenBao as Two Plugin Instances

```bash
docker plugin create vault-secret:latest ./plugin_vault
docker plugin create openbao-secret:latest ./plugin_openbao
```

### One Service Using Both Providers

```yaml
services:
  app:
    image: busybox:latest
    secrets:
      - vault_secret
      - openbao_secret
```

### Two Services Using Different Providers

```yaml
services:
  app_vault:
    image: busybox:latest
    secrets:
      - vault_secret
```

## Provider-Specific Notes

### AWS Secrets Manager
- Supports IAM roles, access keys, and profiles
- JSON secrets are parsed automatically

### Azure Key Vault
- Uses REST API with OAuth2 authentication
- Supports service principals and managed identities

### OpenBao
- Fully compatible with Vault API
- Supports all Vault authentication methods

### GCP Secret Manager
- Future implementation will support service accounts and ADC
