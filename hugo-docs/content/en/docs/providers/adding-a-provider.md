---
title: Adding a Provider
type: docs
weight: 16
---

To add a new backend such as 1Password later:

1. Implement the provider interface behind the same fetch and rotation contract.
2. Keep configuration loading provider-specific and validated at startup.
3. Add a provider page with env vars, labels, and auth examples.
4. Add smoke coverage for secret fetch and rotation behavior.
5. Update the provider matrix on the docs landing page.
