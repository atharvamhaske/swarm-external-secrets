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
| `AWS_ROLE_ARN` | optional | none | IAM role for web identity federation |
| `AWS_WEB_IDENTITY_TOKEN_FILE` | optional | none | Mounted token file used for `AssumeRoleWithWebIdentity` |
| `AWS_ROLE_SESSION_NAME` | optional | none | Optional session name for web identity auth |
| `AWS_SPIFFE_JWT_AUDIENCE` | optional | none | Fetches JWT-SVID directly from the SPIRE Workload API |
| `SPIFFE_ENDPOINT_SOCKET` | optional | none | SPIRE Workload API socket URI, for example `unix:///run/spire/sockets/agent.sock` |

The provider loads normal AWS SDK config first, then overrides credentials if explicit access keys are set.
If `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` are both set, the AWS SDK uses web identity federation.
If `AWS_ROLE_ARN` and `AWS_SPIFFE_JWT_AUDIENCE` are both set, the plugin fetches a fresh JWT-SVID from the SPIRE Workload API and uses `AssumeRoleWithWebIdentity` directly.

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

## Web Identity Example

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ROLE_ARN="arn:aws:iam::123456789012:role/swarm-secrets" \
    AWS_WEB_IDENTITY_TOKEN_FILE="/run/swarm-external-secrets/aws-web-identity-token" \
    AWS_ROLE_SESSION_NAME="swarm-external-secrets"
```

## Direct SPIFFE Workload API Example

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ROLE_ARN="arn:aws:iam::123456789012:role/swarm-secrets" \
    AWS_SPIFFE_JWT_AUDIENCE="awssm" \
    SPIFFE_ENDPOINT_SOCKET="unix:///run/spire/sockets/agent.sock"
```

For multi-role isolation in Swarm, run one plugin instance per AWS role and point each service at the correct plugin name.

## Testing web identity (real AWS)

Test in three steps: LocalStack smoke for provider logic (`scripts/tests/smoke-test-awssm.sh`), then STS + Secrets Manager with only web identity (`scripts/tests/aws-web-identity-probe.sh`), then full plugin + Swarm (`scripts/tests/smoke-test-awssm-web-identity.sh`). See the repo doc `docs/aws-web-identity-poc.md` for environment variables and checklist.

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
