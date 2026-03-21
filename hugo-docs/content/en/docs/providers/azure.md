---
title: Azure Key Vault
type: docs
weight: 13
---

Azure Key Vault supports direct secret lookup, JSON field extraction, service-principal auth, and the default Azure credential chain.

## Environment Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SECRETS_PROVIDER` | no | `azure` | Selects the provider |
| `AZURE_VAULT_URL` | yes | none | Vault base URL |
| `AZURE_TENANT_ID` | optional | none | Used for service principal auth |
| `AZURE_CLIENT_ID` | optional | none | Used for service principal auth |
| `AZURE_CLIENT_SECRET` | optional | none | Used for service principal auth |
| `AZURE_ACCESS_TOKEN` | listed in plugin config | none | Present in config surface, but current provider uses the SDK credential chain |

## Authentication Behavior

The provider prefers service principal credentials when all of these are present:

- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`

If those are missing, it falls back to `DefaultAzureCredential`, which can use managed identity, Azure CLI login, or other standard Azure SDK sources.

## Basic Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="https://myvault.vault.azure.net/" \
    AZURE_TENANT_ID="<tenant-id>" \
    AZURE_CLIENT_ID="<client-id>" \
    AZURE_CLIENT_SECRET="<client-secret>"
```

## Secret Labels

- `azure_secret_name`
- `azure_field`

## Naming Rules

If `azure_secret_name` is set, the provider uses it directly.

Otherwise it builds a name from the request:

- `<service>-<secret>` when a service name is present
- `<secret>` otherwise

Invalid characters are replaced with `-`, duplicate dashes are collapsed, and empty names fall back to `default-secret`.

## Field Extraction

If `azure_field` is set, the stored secret must be valid JSON and the requested key is returned.

If no field is set, the provider:

- tries `value`, `password`, `secret`, `data`
- then falls back to the first string value in the JSON object
- otherwise returns the full raw secret string

## Docker Compose Example

```yaml
secrets:
  database_connection:
    driver: swarm-external-secrets:latest
    labels:
      azure_secret_name: "database-connection-string"
```

## Rotation Notes

Azure supports rotation checks. The plugin fetches the secret again, extracts the selected field if needed, and compares hashes to detect changes.
