---
title: Monitoring
linkTitle: Monitoring
type: docs
description: Monitoring dashboard, Prometheus metrics, and health endpoints
weight: 20
---

The plugin includes a built-in monitoring system for tracking system performance, secret rotation activity, and overall health.

## Configuration

| Variable | Description | Default |
|---|---|---|
| `ENABLE_MONITORING` | Enable monitoring | `true` |
| `MONITORING_PORT` | Web interface port | `8080` |
| `ROTATION_INTERVAL` | Rotation check interval | `10s` |

## Web Dashboard

Access the dashboard at `http://localhost:8080`.

## API Endpoints

### `/metrics` — JSON Metrics

### `/health` — Health Check

### `/api/metrics` — Prometheus Format

## Prometheus Integration

```yaml
scrape_configs:
  - job_name: 'vault-swarm-plugin'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/api/metrics'
```

## Grafana Queries

```promql
vault_swarm_plugin_goroutines
vault_swarm_plugin_memory_bytes{type="alloc"}
```

## Troubleshooting

### Ticker Unhealthy

- Check rotation interval configuration
- Verify no blocking operations in rotation

### High Error Rate

- Review provider authentication
- Check network connectivity

### Memory Growth

- Check for goroutine leaks
- Monitor secret tracker growth
