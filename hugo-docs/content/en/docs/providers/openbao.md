---
title: OpenBao
type: docs
weight: 14
---

## Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="https://openbao.example.com:8200" \
    OPENBAO_TOKEN="<token>"
```

## Secret Labels

- `openbao_path`
- `openbao_field`
