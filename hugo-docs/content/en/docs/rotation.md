---
title: Secret Rotation
linkTitle: Rotation
type: docs
description: Automatic secret rotation and change detection
weight: 30
---

The plugin automatically monitors secrets and updates Docker Swarm secrets and services when changes are detected in the external provider.

## How It Works

1. **Secret Tracking**: the plugin tracks the mapping between the Docker secret and provider path.
2. **Background Monitoring**: a background goroutine periodically checks for changes by comparing SHA256 hashes.
3. **Automatic Rotation**: when a change is detected, a new Docker secret is created and services are updated.

## Configuration

| Variable | Description | Default |
|---|---|---|
| `ENABLE_ROTATION` | Enable/disable automatic rotation | `true` |
| `ROTATION_INTERVAL` | How often to check for changes | `10s` |

## Usage Example

```yaml
secrets:
  mysql_password:
    driver: swarm-external-secrets:latest
    labels:
      vault_path: "database/mysql"
      vault_field: "password"
```

## Monitoring Rotation

```bash
sudo journalctl -u docker.service -f | grep vault
docker service logs <service-name>
```
