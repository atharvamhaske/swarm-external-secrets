---
title: AWS Secrets Manager
type: docs
weight: 12
---

## Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ACCESS_KEY_ID="<key>" \
    AWS_SECRET_ACCESS_KEY="<secret>"
```

## Secret Labels

- `aws_secret_name`
- `aws_field`
