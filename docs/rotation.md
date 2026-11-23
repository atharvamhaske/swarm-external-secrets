# Secret Rotation

This document describes the automatic secret rotation feature of the Swarm External Secrets plugin.

## Overview

The plugin monitors tracked secrets in providers that support rotation, including Doppler, and updates the corresponding Docker Swarm secrets and services when changes are detected.

Polling is the default. Vault also supports an opt-in HTTP notification listener
with `USE_WEBHOOK=true`; a healthy listener replaces periodic polling. See
[Vault webhook synchronization](webhooks.md) for configuration, sender
requirements, retry behavior, and the current HCP compatibility limitation.

This is **secret value** rotation. Keeping the plugin logged in to Vault or OpenBao
(AppRole/JWT client-token renew-self and re-login) is documented separately in
[Vault and OpenBao JWT](jwt.md). A static `VAULT_TOKEN` or `OPENBAO_TOKEN` is
not renewed.

## How It Works

1. **Secret Tracking**: When a Docker service requests a secret, the plugin tracks the mapping between the Docker secret and its provider path or key.

2. **Change Detection**: In polling mode, a background goroutine checks the provider by comparing SHA256 hashes of secret values. Vault webhook events can trigger checks instead of polling; a listener startup failure falls back to polling. Doppler webhooks add checks between polling intervals. A repeated request from another consumer does not acknowledge a change before existing services rotate.

3. **Automatic Rotation**: When a change is detected:
   - A new version of the Docker secret is created with the updated value
   - Services using the secret are automatically updated to trigger redeployment
   - The old secret version is removed

## Configuration

The following environment variables control the rotation behavior:

| Variable | Description | Default |
|---|---|---|
| `ENABLE_ROTATION` | Enable/disable automatic rotation | `true` |
| `ROTATION_INTERVAL` | How often to check for changes | `10s` |
| `USE_WEBHOOK` | Use the Vault notification listener instead of periodic polling | `false` |
| `LOG_LEVEL` | Optional log level integer `0-6` (use `6` for trace) | `4` (info) |

For Vault and OpenBao, rotation tracking uses the same configured mount path as normal secret reads:

- Default KV mount: `secret`
- Custom mounts are supported via `VAULT_MOUNT_PATH` and `OPENBAO_MOUNT_PATH`
- Example custom mounts: `kv`, `prod`, `dev`

If a custom mount path is configured, rotation monitoring checks that mount instead of assuming `secret/data/...`.

### Doppler Caching and Webhooks

Normal Doppler reads reuse cached values for `DOPPLER_CACHE_TTL` (default `30s`).
Each rotation cycle invalidates that cache and fetches the tracked secret names
once per project and config, so a long cache TTL does not delay change detection
until the TTL expires.

Signed webhooks can trigger a reconciliation between polling intervals. The
listener requires `ENABLE_ROTATION=true` and `DOPPLER_WEBHOOK_ENABLE=true`.
Configure `DOPPLER_WEBHOOK_SECRET` to verify deliveries; unsigned requests require
an explicit development-only option. Polling continues when webhooks are enabled.
See the [Doppler guide](doppler.md#signed-webhooks) for configuration and tests.

### Example Configuration

```bash
# Enable rotation with 2-minute check interval
docker plugin set swarm-external-secrets:latest \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="2m"

# Disable rotation
docker plugin set swarm-external-secrets:latest \
    ENABLE_ROTATION="false"
```

## Usage Example

1. **Deploy a service with Vault secrets**:
   ```yaml
   secrets:
     mysql_password:
       driver: swarm-external-secrets:latest
       labels:
         vault_path: "database/mysql"
         vault_field: "password"
   ```

2. **Update the secret in Vault**:
   ```bash
   vault kv put secret/database/mysql password=new_secure_password
   ```

### Custom Mount Path Example

If Vault or OpenBao is mounted somewhere other than `secret`, configure the plugin with the matching mount path so rotation tracking monitors the correct backend:

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="http://127.0.0.1:8200" \
    VAULT_TOKEN="root" \
    VAULT_MOUNT_PATH="kv"
```

Then a secret such as `kv/data/database/mysql` is tracked and rotated against the configured `kv` mount instead of the default `secret` mount.

3. **Automatic rotation**: In polling mode, within the next rotation interval (default 10 seconds), the plugin will:
   - Detect the change in Vault
   - Update the Docker secret with the new value
   - Force update services using the secret

## Monitoring

Check plugin logs to monitor rotation activity:

```bash
# View plugin logs from the shared host file
tail -F /run/swarm-external-secrets/plugin.log

# Filter rotation events
tail -F /run/swarm-external-secrets/plugin.log | grep -E "rotation|Failed to rotate|Detected change"
```

On Linux, the default plugin log path is `/run/swarm-external-secrets/plugin.log`.
macOS and Windows filesystems do not support this `/run/**` path by default. On
those hosts, create a log directory with read/write permissions and set
`PLUGIN_LOG_PATH` to that file:

```bash
mkdir -p ./logs
touch ./logs/plugin.log
docker plugin set swarm-external-secrets:latest \
  PLUGIN_LOG_PATH="$PWD/logs/plugin.log"
```

You can also expose these logs through the bundled compose override:

```bash
sudo mkdir -p /run/swarm-external-secrets
sudo touch /run/swarm-external-secrets/plugin.log
docker compose -f docker-compose.yml -f docker-compose.logs.yml up -d
docker compose -f docker-compose.yml -f docker-compose.logs.yml logs -f secrets-logger
```

The sidecar service in `docker-compose.logs.yml` is:

```yaml
services:
  secrets-logger:
    image: alpine:3.20
    command: sh -c "tail -F /run/swarm-external-secrets/plugin.log"
    volumes:
      - /run/swarm-external-secrets:/run/swarm-external-secrets:ro
```

## Benefits

- **Zero downtime**: Services are updated gracefully
- **Automatic synchronization**: No manual intervention required
- **Security**: Old secrets are automatically cleaned up
- **Auditability**: All rotation events are logged

## Limitations

- Services must support graceful secret updates (restart when secrets change)
- Polling frequency is limited by the configured interval; Doppler webhooks can trigger an additional check between polls
- Vault webhook mode requires a separate sender and retries for failed or busy requests; missed events have no periodic polling recovery while its listener is healthy
- Docker Swarm must be running in manager mode for secret management

## Troubleshooting

If rotation is not working:

1. Check if rotation is enabled: `ENABLE_ROTATION=true`
2. Verify plugin has access to Docker socket
3. Ensure plugin is running on a manager node
4. Check plugin logs for error messages
5. Verify connectivity and permissions for the configured provider

## Security Considerations

- The plugin requires Docker socket access to manage secrets and services
- Ensure proper Vault authentication and minimal required permissions
- Secret rotation tracking can include sensitive metadata (paths/fields/service mappings) at `trace` level. Keep production log level at `info`/`warn` unless actively debugging.
- Monitor logs for unauthorized rotation attempts
- Consider using shorter rotation intervals for highly sensitive secrets
