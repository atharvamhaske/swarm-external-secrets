---
title: Swarm External Secrets
linkTitle: Docs
type: docs
weight: 1
---

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sugar-org/swarm-external-secrets/badge)](https://scorecard.dev/viewer/?uri=github.com/sugar-org/swarm-external-secrets)
[![Join our Discord](https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white)](https://discord.gg/4NYdBu7bZy)

---

A Docker Swarm secrets plugin that integrates with multiple secret management providers including HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, OpenBao, and Doppler.

## Updates

### Google Summer of Code 2026

swarm-external-secrets is participating in Google Summer of Code 2026 incubated under the organization [OpenScienceLabs](http://opensciencelabs.org/)!

For more information, check out the [GSoC Contribution Guidelines](contributing/#google-summer-of-code-2026).

## Architecture

![Architecture](https://raw.githubusercontent.com/sugar-org/swarm-external-secrets/refs/heads/main/docs/architecture.png)

## Supported Providers

| Provider | Status | Authentication | Rotation |
|----------|--------|---------------|----------|
| HashiCorp Vault | Stable | Token, AppRole | Yes |
| AWS Secrets Manager | Stable | IAM, Access Keys | Yes |
| Azure Key Vault | Stable | Service Principal, Managed Identity | Yes |
| OpenBao | Stable | Token, AppRole | Yes |
| GCP Secret Manager | Beta | Service Account, ADC | Yes |
| Doppler | Beta | Service token (`DOPPLER_KEY` / `DOPPLER_TOKEN`) | Yes |

## Features

- **Multi-Provider Support** — HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, OpenBao, Doppler
- **Multiple Auth Methods** — Support for various authentication methods per provider
- **Automatic Secret Rotation** — Monitor providers for changes and automatically update Docker secrets and services
- **Real-time Monitoring** — Web dashboard with system metrics, health status, and performance tracking
- **Flexible Path Mapping** — Customize secret paths and field extraction per provider
- **Production Ready** — Proper error handling, logging, cleanup, and monitoring
- **Backward Compatible** — Existing Vault configurations continue to work unchanged
