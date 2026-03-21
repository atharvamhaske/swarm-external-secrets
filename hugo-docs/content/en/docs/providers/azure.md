---
title: Azure Key Vault
type: docs
weight: 13
---

## Configuration

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
