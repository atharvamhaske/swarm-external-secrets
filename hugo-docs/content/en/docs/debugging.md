---
title: Debugging
linkTitle: Debugging
type: docs
description: Useful commands for debugging the plugin
weight: 40
---

## Start a Dev Vault Server

```bash
vault server -dev
```

## Create an AppRole

```bash
vault write auth/approle/role/my-role \
    token_policies="default,web-app"
```

## Retrieve the Role ID

```bash
vault read auth/approle/role/my-role/role-id
```

## Get the Secret ID

```bash
vault write -f auth/approle/role/my-role/secret-id
```

## Login with AppRole

```bash
vault write auth/approle/login \
    role_id="<role-id>" \
    secret_id="<secret-id>"
```

## Set and Get KV Secrets

```bash
vault kv put secret/database/mysql root_password=admin user_password=admin
vault kv get secret/database/mysql
```

## Debug the Plugin

```bash
sudo journalctl -u docker.service -f | grep "$(docker plugin ls --format '{{.ID}}')"
```
