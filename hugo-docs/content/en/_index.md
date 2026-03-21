---
title: Swarm External Secrets
---

{{< blocks/cover title="Swarm External Secrets" image_anchor="top" height="med" color="primary" >}}
<p class="lead mt-4">A Docker Swarm secrets plugin that integrates with multiple external secret management providers.</p>
<div class="mt-4">
<a class="btn btn-lg btn-light me-3 mb-4" href="docs/">
Documentation <i class="fas fa-book ms-2"></i>
</a>
<a class="btn btn-lg btn-outline-light me-3 mb-4" href="https://github.com/sugar-org/swarm-external-secrets">
GitHub <i class="fab fa-github ms-2"></i>
</a>
<a class="btn btn-lg btn-outline-light me-3 mb-4" href="https://discord.gg/4NYdBu7bZy">
Discord <i class="fab fa-discord ms-2"></i>
</a>
</div>
<div class="mt-3">
<a href="https://scorecard.dev/viewer/?uri=github.com/sugar-org/swarm-external-secrets"><img src="https://api.scorecard.dev/projects/github.com/sugar-org/swarm-external-secrets/badge" alt="OpenSSF Scorecard"></a>
<a href="https://discord.gg/4NYdBu7bZy"><img src="https://img.shields.io/badge/Discord-Join%20Server-5865F2?logo=discord&logoColor=white" alt="Join our Discord"></a>
</div>
{{< /blocks/cover >}}

{{% blocks/section color="white" %}}
## Features

- **Multi-Provider Support** — HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, and OpenBao
- **Multiple Auth Methods** — Support for various authentication methods per provider
- **Automatic Secret Rotation** — Monitor providers for changes and automatically update Docker secrets and services
- **Real-time Monitoring** — Web dashboard with system metrics, health status, and performance tracking
- **Flexible Path Mapping** — Customize secret paths and field extraction per provider
- **Production Ready** — Proper error handling, logging, cleanup, and monitoring
- **Backward Compatible** — Existing Vault configurations continue to work unchanged
{{% /blocks/section %}}

{{% blocks/section color="light" %}}
## Supported Providers

| Provider | Status | Authentication | Rotation |
|----------|--------|---------------|----------|
| HashiCorp Vault | Stable | Token, AppRole | Yes |
| AWS Secrets Manager | Stable | IAM, Access Keys | Yes |
| Azure Key Vault | Stable | Service Principal, Managed Identity | Yes |
| OpenBao | Stable | Token, AppRole | Yes |
| GCP Secret Manager | Beta | Service Account, ADC | Yes |
{{% /blocks/section %}}

{{% blocks/section color="white" %}}
## Architecture

![Architecture](https://raw.githubusercontent.com/sugar-org/swarm-external-secrets/refs/heads/main/docs/architecture.png)
{{% /blocks/section %}}

{{% blocks/section color="light" %}}
## Quick Start

```bash
./scripts/build.sh
```

See the [full documentation](docs/) for all provider configurations and advanced usage.
{{% /blocks/section %}}
