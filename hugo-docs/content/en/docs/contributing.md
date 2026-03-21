---
title: Contributing
linkTitle: Contributing
type: docs
description: Contribution workflow, tooling, and GSoC guidance
weight: 50
---

# Contributing to swarm-external-secrets

Thank you for your interest in contributing to **swarm-external-secrets**.

## Getting Started

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | >= 1.24 | Primary language |
| Docker | latest | Plugin build and testing |
| Makim | latest | Task runner |
| Lefthook | latest | Git hooks manager |
| golangci-lint | latest | Go linter |

### Fork and Clone

```bash
git clone https://github.com/<your-username>/swarm-external-secrets.git
cd swarm-external-secrets
git remote add upstream https://github.com/sugar-org/swarm-external-secrets.git
```

### Set Up the Development Environment

```bash
./setup-hooks.sh
go mod download
```

## Development Workflow

```bash
makim scripts.build
makim scripts.test
makim scripts.linter
```

## Adding a New Provider

1. Create a provider implementation under `providers/`.
2. Register the provider in `driver.go`.
3. Add docs under `docs/providers/`.
4. Add smoke or integration coverage.

## Tips for Adding Future Providers

- Keep provider-specific configuration isolated behind a shared interface.
- Reuse the label parsing and rotation workflow instead of duplicating driver logic.
- Document required environment variables and auth flows in a dedicated provider page.
- Follow the same page structure so new providers like 1Password can be added consistently later.

## Google Summer of Code 2026

Please review the project ideas, contribute early, and keep pull requests focused and easy to review.
