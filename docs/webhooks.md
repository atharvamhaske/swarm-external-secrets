# Vault webhook synchronization

The Vault provider can receive HTTP notifications and check tracked secrets for
changes immediately. Polling remains the default. Webhook mode requires a
separate sender; enabling the listener does not create a webhook subscription
inside Vault.

## Compatibility and current limits

The listener accepts the HCP-style JSON envelope described below. Its current
signature algorithm is **HMAC-SHA256**. HashiCorp's
[HCP webhook documentation](https://developer.hashicorp.com/hcp/docs/hcp/admin/projects/webhooks#webhook-authenticity)
specifies **HMAC-SHA512**. Direct HCP interoperability is therefore not supported
by the current signature validator. The listener, tests, and sender must agree
on the documented upstream protocol before direct HCP integration can be used.

The CI test supplies a synthetic notification with `curl` after updating a real
Vault development server. It does not verify automatic event delivery from
Vault or HCP. No Vault-side subscription or event-forwarding service is
installed by this feature.

Use polling when an event sender is unavailable. With a healthy webhook
listener, periodic polling is disabled; missed notifications do not receive a
later polling check. A listener startup failure falls back to polling.

## Configuration

Configuration comes from the plugin's environment. Set these values with
`docker plugin set` while the plugin is disabled, or export them before starting
the binary directly.

| Variable | Default | Behavior |
| --- | --- | --- |
| `SECRETS_PROVIDER` | `vault` | Webhook mode is implemented only for `vault`. Other providers continue polling when rotation is enabled and supported. |
| `ENABLE_ROTATION` | `true` | Must be `true` for the listener to start. |
| `USE_WEBHOOK` | `false` | Set to `true` to use the webhook listener for Vault. |
| `WEBHOOK_PORT` | `9095` | HTTP listener port; use a port from 1 through 65535. |
| `WEBHOOK_SECRET` | Empty | Shared token used to validate the hexadecimal HMAC-SHA256 signature. Empty disables authentication and produces a startup warning. |
| `ROTATION_INTERVAL` | `10s` | Polling interval, including fallback after listener startup failure. Use a positive duration such as `10s` or `2m`. |

Vault connection, authentication, and KV mount settings still apply. See the
[Vault configuration reference](multi-provider.md#1-hashicorp-vault-default)
and [JWT authentication guide](jwt.md).

### Configure a local receiver

Use a disposable Linux Swarm manager for this example. Vault must already be
running and reachable from the plugin, and its token must permit reading the
tracked paths. The build script replaces the local plugin named
`swarm-external-secrets:latest`.

Build this branch without publishing to a registry:

```bash
DOCKER_USERNAME= bash scripts/build.sh
```

For a local development Vault on port 8200, set `VAULT_TOKEN` to its token, then
configure the newly built, disabled plugin:

```bash
: "${VAULT_TOKEN:?Set VAULT_TOKEN to a token that can read the secret}"
export WEBHOOK_SECRET="$(openssl rand -hex 32)"
sudo mkdir -p /run/swarm-external-secrets

docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="http://127.0.0.1:8200" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="${VAULT_TOKEN}" \
    VAULT_MOUNT_PATH="secret" \
    ENABLE_ROTATION="true" \
    USE_WEBHOOK="true" \
    WEBHOOK_PORT="9095" \
    WEBHOOK_SECRET="${WEBHOOK_SECRET}" \
    ROTATION_INTERVAL="10s"
docker plugin enable swarm-external-secrets:latest

curl --fail --silent --show-error http://127.0.0.1:9095/webhook/health
```

The listener binds all host interfaces using HTTP. Restrict access to trusted
senders and use a TLS-terminating proxy when traffic crosses an untrusted
network. HMAC authenticates the body but does not encrypt it or prevent replay.
The health endpoint does not require a signature.

Deploy a service that requests the secret through the plugin, as shown in the
[rotation example](rotation.md#usage-example), before sending an event. Only
secrets already tracked by the driver can be reconciled.

## Request format and manual delivery

Send `POST /webhook` with a JSON body. To trigger a check, use:

- `event_source`: `hashicorp.secrets.secret`, case-insensitive.
- `event_action`: `create`, `update`, or `rotate`, case-insensitive.
- `event_payload.name`: a nonempty secret name. It matches an exact tracked
  Docker secret name or a tracked Vault path ending in `/<name>`. Every matching
  entry is checked, so several fields or Docker names can use the same path.

The driver reads the current secret value from Vault. The event does not carry
the new secret value. Other payload fields are decoded but do not select a
Vault application, namespace, or project. Names shared by different tracked
paths can therefore trigger checks of all those paths.

After updating `secret/database/mysql` in Vault, the following request checks
tracked entries matching `mysql`. Keep `WEBHOOK_SECRET` from the setup step in
the same shell:

```bash
: "${WEBHOOK_SECRET:?Use the same shared secret configured on the plugin}"
payload='{"event_action":"rotate","event_source":"hashicorp.secrets.secret","event_payload":{"name":"mysql"}}'
signature=$(printf '%s' "${payload}" | openssl dgst -sha256 -hmac "${WEBHOOK_SECRET}" -hex)
signature="${signature##* }"

curl --fail --silent --show-error --max-time 140 \
    -H "Content-Type: application/json" \
    -H "X-HCP-Webhook-Signature: ${signature}" \
    --data-binary "${payload}" \
    http://127.0.0.1:9095/webhook
```

Sign the exact raw request bytes, without adding a trailing newline. Hexadecimal
signatures are accepted in either case. When `WEBHOOK_SECRET` is configured,
verification pings with `event_action: "test"` also require a valid signature.

### Responses, retries, and shutdown

| HTTP status | Meaning |
| --- | --- |
| `200` | Reconciliation succeeded, the secret was unchanged or untracked, or the event was a verification ping or ignored because of its source, action, or missing name. It does not always mean a secret was rotated. |
| `400` | The body could not be read or parsed as the expected JSON envelope. |
| `401` | A configured shared secret requires a signature that is missing or invalid. |
| `405` | The webhook request used a method other than POST. |
| `413` | The body exceeds 1 MiB. |
| `503` | Reconciliation failed, another reconciliation is active, or shutdown prevents admission. Failure and busy responses include `Retry-After: 1`. |

Reconciliation runs synchronously, with at most one active reconciliation. Success is
acknowledged after processing finishes. Configure senders to retry `503`
responses with backoff and to allow up to two minutes for reconciliation.
Client cancellation and server shutdown cancel in-flight provider and Docker
calls. Shutdown has a five-second drain budget; rollback of an unused newly
created Docker secret has a separate two-second cleanup timeout.

Event IDs are not stored for deduplication. Retries check the current value
against the tracked hash. A request that matches multiple secrets can complete
some rotations before another fails; its `503` response does not roll back
successful rotations of other matching entries.

## CI smoke-test coverage

The `vault` entry in the
[smoke-test workflow](https://github.com/sciops-org/swarm-external-secrets/blob/main/.github/workflows/smoke-tests.yml)
runs `scripts/tests/smoke-test-vault.sh`. On a disposable Swarm manager, run it
from the repository root with:

```bash
bash scripts/tests/smoke-test-vault.sh
```

The script builds the plugin and replaces its local plugin alias, creates a
Vault development container and test stack, and cleans them up on exit. It
requires Docker, Bash, OpenSSL, `curl`, and privileges to manage the plugin and
Swarm. Its sequence is:

1. Start Vault and write an initial secret.
2. Build and enable the plugin in webhook mode with a test shared secret and a
   one-hour polling interval.
3. Wait for the listener's health endpoint, deploy a service that requests the
   secret, and verify its initial value.
4. Change the Vault value with `vault kv put`.
5. Construct and sign a synthetic HCP-style rotation event with OpenSSL, then
   POST it to the plugin using `curl`.
6. Verify the application receives the rotated secret.

The long polling interval helps distinguish webhook-triggered rotation from
polling fallback during this test. The test does not configure a native Vault
notification subscription or validate HCP event delivery and signature
compatibility. The OpenBao smoke test continues to use polling.

## Troubleshooting

- **No listener:** check `ENABLE_ROTATION=true`, `USE_WEBHOOK=true`, and
  `SECRETS_PROVIDER=vault`, then inspect the plugin logs for bind errors and
  fallback-to-polling messages.
- **401:** check the shared token and the exact bytes being signed. Real HCP
  SHA-512 signatures are incompatible with the current SHA-256 implementation.
- **200 without rotation:** check that a service requested the secret, the event
  source/action is accepted, and the name matches a tracked entry. An unchanged
  value also returns success.
- **503:** inspect provider and Docker connectivity, permissions, and timeout
  logs. Retry after the advertised delay when the receiver is busy.
- **No sender available:** configure `USE_WEBHOOK=false` while the plugin is
  disabled and re-enable it to restore periodic checks.
