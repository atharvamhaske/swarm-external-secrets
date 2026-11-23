# Doppler

The Doppler provider reads secrets through the Doppler REST v3 API and supports
polling-based rotation and optional signed webhooks. The
[configuration reference](multi-provider.md#6-doppler) lists all environment
variables, defaults, and secret labels.

## Configure the Provider

Use a [service token](https://docs.doppler.com/docs/service-tokens) (`dp.st.*`) scoped to the project and config containing your
secrets. Service tokens do not require `DOPPLER_PROJECT` or `DOPPLER_CONFIG`.
For a CLI or personal token, both variables are required.

Configure an installed, disabled plugin, then enable it:

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="doppler" \
    DOPPLER_TOKEN="dp.st.example" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="30s"

docker plugin enable swarm-external-secrets:latest
```

The default API origin is `https://api.doppler.com`. An override must be an
origin without an API path or query: the client adds
`/v3/configs/config/secrets/download`. HTTP is allowed only for loopback hosts,
and redirects are rejected.

## Use a Secret in a Stack

Create `API_KEY` in the Doppler config accessible to your token. Save the following
as `stack.yml`:

```yaml
services:
  app:
    image: busybox:latest
    command: ["sleep", "3600"]
    secrets:
      - api_key

secrets:
  api_key:
    driver: swarm-external-secrets:latest
    labels:
      doppler_secret_name: "API_KEY"
```

Deploy on a Swarm manager:

```bash
docker stack deploy -c stack.yml doppler-demo
```

The container receives the value at `/run/secrets/api_key`. Replace the sample
service with your application and read that file there. An explicit
`doppler_secret_name` avoids depending on Docker's stack-prefixed secret name;
without the label, the plugin uppercases the Docker secret name.

The `doppler_project` and `doppler_config` labels can override the plugin defaults
per secret. They do not broaden the token's permissions. For separate service-token
scopes, use separate plugin instances.

## Rotation and Caching

Change `API_KEY` in Doppler to rotate it. With `ENABLE_ROTATION=true`, the plugin
checks tracked secrets at `ROTATION_INTERVAL`, creates a new Docker secret version,
and updates services that reference the old version. Services redeploy to receive
the new value.

Normal reads are cached for `DOPPLER_CACHE_TTL` (default `30s`; `0s` disables cached
value reuse). Rotation refreshes the tracked keys once per project and config,
so a long cache TTL does not hide a changed value until expiry. Network failures,
HTTP 429, and retryable 5xx responses have bounded retries with jitter and honor
`Retry-After`.

## Signed Webhooks

To trigger rotation between polling intervals, configure these additional settings
while the plugin is disabled, then enable it:

```bash
docker plugin set swarm-external-secrets:latest \
    ENABLE_ROTATION="true" \
    DOPPLER_WEBHOOK_ENABLE="true" \
    DOPPLER_WEBHOOK_PORT="8081" \
    DOPPLER_WEBHOOK_PATH="/webhooks/doppler" \
    DOPPLER_WEBHOOK_SECRET="<your-signing-secret>"
```

In Doppler's project Webhooks settings, select the relevant configs, set the
delivery URL, and set the Secret field to the same value as
`DOPPLER_WEBHOOK_SECRET`. See [Doppler's webhook setup instructions](https://docs.doppler.com/docs/webhooks).
The plugin verifies the `X-Doppler-Signature` HMAC-SHA256 header before processing
`config.secrets.update` events. It also accepts custom payloads that omit `type`.

The listener serves HTTP on the host network at
`http://<host>:8081/webhooks/doppler`. Terminate HTTPS at a reverse proxy when
exposing it outside the host. Its path must begin with `/` and cannot contain
wildcards or whitespace. The listener does not start when rotation is disabled.

Deliveries are asynchronous: one check runs at a time, and bursts coalesce into
one pending check. Polling remains active. A signing secret is required unless
`DOPPLER_WEBHOOK_INSECURE=true`, which accepts unsigned requests and is intended
only for local development.

## Smoke Tests

Run tests from the repository root on a disposable Linux Swarm manager with Docker
CLI access, Go 1.25 or later, `curl`, and `openssl`. The scripts build, install, and
remove `swarm-external-secrets:latest`, create and remove their test stacks, and
clean up their mock processes. Use a test manager where these operations are safe.

### Local Mock: No Doppler Account Required

An empty `DOPPLER_SMOKE_TOKEN` selects the local mock API at
`http://127.0.0.1:18080`. Run these sequentially:

```bash
DOPPLER_SMOKE_TOKEN= bash scripts/tests/smoke-test-doppler.sh
DOPPLER_SMOKE_TOKEN= bash scripts/tests/smoke-test-doppler-webhook.sh
```

The scripts compile the mock before starting its readiness deadline. Both verify
initial retrieval and rotation after updating the backend. The webhook test uses
a one-hour polling interval and cache TTL, rejects an invalid signature, and
checks that a valid signed delivery rotates the service's secret.

### Live Doppler Config

A non-empty `DOPPLER_SMOKE_TOKEN` selects the live API. Use a read/write service
token for a dedicated test config: the scripts create, update, and delete
run-specific test keys. This token needs write permissions even though the plugin
itself only reads secrets.

```bash
DOPPLER_SMOKE_TOKEN="dp.st.example" bash scripts/tests/smoke-test-doppler.sh
DOPPLER_SMOKE_TOKEN="dp.st.example" bash scripts/tests/smoke-test-doppler-webhook.sh
```

`DOPPLER_PROJECT` and `DOPPLER_CONFIG` are optional overrides for these tests;
the service token remains restricted to its own scope. The webhook test generates
its own signed HTTP deliveries even in live mode. Pull-request CI uses the mock;
the workflow only supplies the configured smoke token for pushes to `main`.
