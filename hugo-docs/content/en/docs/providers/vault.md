---
title: HashiCorp Vault
type: docs
weight: 11
---

## Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_TOKEN="hvs.example-token"
```

## Secret Labels

- `vault_path`
- `vault_field`

## Authentication

- Token
- AppRole
