---
title: GCP Secret Manager
type: docs
weight: 15
---

## Status

This provider is currently placeholder or partial depending on the branch state. Verify implementation details before using it in production.

## Expected Configuration

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="gcp" \
    GCP_PROJECT_ID="<project-id>"
```
