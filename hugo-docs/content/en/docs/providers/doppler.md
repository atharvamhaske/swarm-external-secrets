---
title: Doppler
type: docs
weight: 17
description: Doppler secrets for Docker Swarm via swarm-external-secrets
---

[Doppler](https://www.doppler.com/) stores secrets per **project** and **config** (environment). This provider uses the [dilutedev/doppler](https://github.com/dilutedev/doppler) Go client and the [Doppler API](https://docs.doppler.com/).

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRETS_PROVIDER` | yes | Set to `doppler` |
| `DOPPLER_KEY` | yes* | API token (format validated by the SDK; service tokens recommended) |
| `DOPPLER_TOKEN` | yes* | Alias for `DOPPLER_KEY` if you prefer this name |
| `DOPPLER_PROJECT` | usually | Default project name |
| `DOPPLER_CONFIG` | usually | Default config / environment name (e.g. `dev`) |

\* One of `DOPPLER_KEY` or `DOPPLER_TOKEN` is required.

You can override `DOPPLER_PROJECT` / `DOPPLER_CONFIG` per Swarm secret with labels.

## Swarm secret labels

| Label | Description |
|-------|-------------|
| `doppler_secret` | Secret **name** (key) inside the Doppler config |
| `doppler_project` | Optional override of `DOPPLER_PROJECT` |
| `doppler_config` | Optional override of `DOPPLER_CONFIG` |

If `doppler_secret` is omitted, the Docker secret **name** is used as the Doppler secret name.

## Plugin configuration example

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="doppler" \
    DOPPLER_KEY="dp.st.…" \
    DOPPLER_PROJECT="my-project" \
    DOPPLER_CONFIG="dev"
```

## Docker Compose / stack example

```yaml
secrets:
  api_key:
    driver: swarm-external-secrets:latest
    labels:
      doppler_secret: "API_KEY"
```

## Rotation

Rotation uses the same mechanism as other providers: the plugin polls the provider, compares a SHA-256 hash of the value, and updates the Docker secret when the value changes in Doppler.

## Smoke test

With a Swarm manager and Docker plugin build in place:

1. In Doppler, create secret **`SMOKE_PLUGIN_TEST`** in your project/config with a known value.
2. Export `DOPPLER_KEY` (or `DOPPLER_TOKEN`), `DOPPLER_PROJECT`, `DOPPLER_CONFIG`, and `DOPPLER_SMOKE_VALUE` (matching that secret).
3. Run:

```bash
bash scripts/tests/smoke-test-doppler.sh
```

Optional: set `DOPPLER_SMOKE_VALUE_ROTATED` to a new value; the script updates the secret via the Doppler HTTP API and verifies rotation.

If required variables are unset, the script **exits 0** (skip) so CI without Doppler credentials does not fail.
