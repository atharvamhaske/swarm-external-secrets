---
title: GCP Secret Manager
type: docs
weight: 15
---

GCP Secret Manager is implemented in the provider code and supports direct secret access, JSON field extraction, ADC or explicit credentials, and rotation checks.

## Environment Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SECRETS_PROVIDER` | no | `gcp` | Selects the provider |
| `GCP_PROJECT_ID` | usually yes | none | Needed for default secret name construction |
| `GOOGLE_APPLICATION_CREDENTIALS` | optional | none | Path to service account credentials |
| `GCP_CREDENTIALS_JSON` | optional | none | Inline service account JSON |

If no explicit credentials are provided, the provider falls back to Application Default Credentials.

## Basic Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="gcp" \
    GCP_PROJECT_ID="<project-id>"
```

## Secret Labels

- `gcp_secret_name`
- `gcp_field`

## Naming Rules

If `gcp_secret_name` is set, the provider uses it directly.

Otherwise it builds:

`projects/<project-id>/secrets/<secret-name>`

When a service name exists, the generated secret name becomes `<service>-<secret>`.

## Field Extraction

If `gcp_field` is set, the provider expects a JSON secret and returns the matching key.

If no field is set, the provider:

- tries `value`, `password`, `secret`, `data`
- then falls back to the first string value in the JSON object
- otherwise returns the raw secret string

## Docker Compose Example

```yaml
secrets:
  app_config:
    driver: swarm-external-secrets:latest
    labels:
      gcp_secret_name: "projects/my-project/secrets/app-config"
      gcp_field: "password"
```

## Rotation Notes

The provider reads `versions/latest`, extracts the effective value, and compares hashes to detect changes.
