---
title: AWS Secrets Manager
type: docs
weight: 12
---

AWS Secrets Manager supports direct string secrets, JSON secrets with field extraction, custom secret names, and rotation tracking.

## Environment Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SECRETS_PROVIDER` | no | `aws` | Selects the provider |
| `AWS_REGION` | no | `us-east-1` | Target region |
| `AWS_ACCESS_KEY_ID` | optional | none | Static credentials |
| `AWS_SECRET_ACCESS_KEY` | optional | none | Static credentials |
| `AWS_PROFILE` | optional | none | Shared config profile |
| `AWS_ENDPOINT_URL` | optional | none | Useful for LocalStack or custom endpoints |

The provider loads normal AWS SDK config first, then overrides credentials if explicit access keys are set.

## Basic Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ACCESS_KEY_ID="<key>" \
    AWS_SECRET_ACCESS_KEY="<secret>"
```

## LocalStack Example

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-east-1" \
    AWS_ACCESS_KEY_ID="test" \
    AWS_SECRET_ACCESS_KEY="test" \
    AWS_ENDPOINT_URL="http://localhost:4566"
```

## Secret Labels

- `aws_secret_name`
- `aws_field`

## Naming Rules

If `aws_secret_name` is set, the provider uses it directly.

Otherwise the secret name becomes:

- `<service>/<secret>` when a service name is present
- `<secret>` when there is no service name

## Field Extraction

If the secret value is JSON, `aws_field` can select a specific key.

If no field is set, the provider tries:

- `value`
- `password`
- `secret`
- `data`

If the stored secret is a plain string instead of JSON, the raw string is returned.

## Docker Compose Example

```yaml
secrets:
  api_key:
    driver: swarm-external-secrets:latest
    labels:
      aws_secret_name: "prod/api/key"
      aws_field: "api_key"
```

## Rotation Notes

AWS supports rotation checks. The plugin re-reads the current secret value, extracts the selected field, and compares the hash against the last synced version.
