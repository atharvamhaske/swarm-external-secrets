# Deep Explainer — Swarm External Secrets

This companion to `ONBOARDING.md` teaches the ideas the code assumes you already know. Each section leads with a plain-language answer, then grounds it in real code from this repo. Read it when a term or mechanism in onboarding still feels fuzzy.

---

## What is a Docker Swarm “secrets plugin,” really?

It is a small program Docker Engine loads and calls over a Unix socket whenever Swarm needs the bytes for a secret that was declared with that plugin as its driver.

Swarm secrets normally work like this: you create a secret with `docker secret create`, Swarm stores the ciphertext in its Raft store, and tasks receive the plaintext as a file under `/run/secrets/`. A **secrets plugin** replaces the “Swarm already has the bytes” step with “ask this external program for the bytes.” The Engine still mounts the result into the container the same way; only the *source* of the value changes.

In this repo that program is the binary built from `main.go`. Docker discovers it via `config.json` (socket name `plugin.sock`, entrypoint `./swarm-external-secrets`, mounts for the Docker socket and log directory). `main.go` wires the pieces:

```go
// main.go — simplified narration of the real startup path
driver, err := NewDriver()                    // build SecretsDriver + provider
handler := secrets.NewHandler(driver)         // adapt Driver → HTTP plugin protocol
handler.ServeUnix("plugin", 0)                // listen on plugin.sock (name must match config.json)
```

Why Unix socket, not HTTP on a port? Docker’s plugin model for secrets is local and host-scoped: the Engine on that node talks to a socket in the plugin’s runtime directory. That keeps the secret fetch path on-node and avoids exposing a network listener for secret material by default (the optional monitoring UI on `:8080` is a separate concern).

You’ll see this idea again every time you debug “plugin enabled but services can’t resolve secrets” — the failure is almost always socket name mismatch, plugin not enabled, or the provider failing inside `Get`, not Swarm’s mount machinery.

---

## What does `SecretsDriver.Get` actually do?

`Get` is the single request handler Docker calls when a service needs a secret. It translates Docker’s request into a provider fetch and returns bytes (or an error).

Think of it as a receptionist: Docker walks up with a form (`secrets.Request` — secret name, service name, labels), and `Get` either returns the value or explains why it can’t. The real function in `driver.go` does five things in order:

1. Reject empty `SecretName`
2. Translate the request once via `buildSecretInfo`
3. Call `provider.GetSecret` with a 30s timeout
4. Optionally `trackSecret` for rotation
5. Set `DoNotReuse` via `shouldNotReuse` and return

```go
// driver.go — the heart of the plugin protocol
func (d *SecretsDriver) Get(req secrets.Request) secrets.Response {
    if req.SecretName == "" {
        return secrets.Response{Err: "secret name is required"}
    }

    secretInfo := d.buildSecretInfo(req) // edge translation lives HERE

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    value, err := d.provider.GetSecret(ctx, secretInfo)
    if err != nil {
        return secrets.Response{Err: fmt.Sprintf("failed to get secret: %v", err)}
    }

    if d.config.EnableRotation && d.provider.SupportsRotation() {
        d.trackSecret(secretInfo, value)
    }

    return secrets.Response{
        Value:      value,
        DoNotReuse: d.shouldNotReuse(req),
    }
}
```

The design reason for “translate once at the edge” (`buildSecretInfo`) is practical: rotation later needs the same path/field/labels without re-parsing Docker’s request shape. If path logic were scattered across `Get`, `hasSecretChanged`, and `rotateSecret`, a label rename would break three places. One translation point is why PR #147 mattered.

---

## What is `SecretsProvider`, and why not just `if provider == "vault"` everywhere?

`SecretsProvider` is an interface that every backend must satisfy so the driver can treat Vault, AWS, Azure, GCP, and OpenBao the same after startup.

Without it, `driver.go` would fill with provider-specific branches — different label names, different SDK calls, different auth setup. The interface pushes that diversity behind one door:

```go
// providers/interface.go
type SecretsProvider interface {
    Initialize(config map[string]string) error
    GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error)
    SupportsRotation() bool
    GetSecretFieldLabel() string  // e.g. "vault_field" vs "aws_field"
    BuildSecretPath(req secrets.Request) string
    GetProviderName() string
    Close() error
}
```

`CreateProvider` in `providers/factory.go` is the *only* switch that picks a concrete type from `SECRETS_PROVIDER`. After `NewDriver` calls `Initialize`, the rest of the driver holds an interface value. That is why adding a provider is “new file + factory case + labels/docs/smoke,” not “thread a new `else if` through rotation.”

Analogy: the driver is a power strip; each provider is a different plug adapter. The strip only cares that something implements the interface — not whether the wall socket is Vault or AWS.

---

## Why does rotation create a *new* Docker secret instead of updating the old one?

Because Swarm secrets are effectively immutable: you create them with data, and you do not overwrite that data in place. To change what a service sees, you create a new secret object and point the service at the new ID.

That constraint shapes the whole rotation pipeline in `updateDockerSecret`:

1. Find the existing secret by name (`SecretList`)
2. `SecretCreate` a versioned name like `mysql_password-1710000000123456789`
3. Rewrite every service that referenced the old ID (`ServiceUpdate`)
4. Remove the old secret

```go
// driver.go — cutover, not in-place edit
newSecretName := fmt.Sprintf("%s-%d", secretName, time.Now().UnixNano())
createResponse, err := d.dockerClient.SecretCreate(ctx, newSecretSpec)
// ...
err = d.updateServicesSecretReference(secretName, existingSecret.ID, newSecretName, createResponse.ID)
// only then:
d.dockerClient.SecretRemove(ctx, existingSecret.ID)
```

If service update fails, the code deletes the *new* secret and returns an error — better to keep the old working reference than leave services half-migrated and accumulate orphaned secrets.

This is also why `buildUpdatedSecretReferences` has careful ID/name matching tests in `driver_test.go`: a naive prefix match on secret names can collide (`db` vs `db-backup`). Rotation correctness is Swarm graph surgery, not just “write new bytes.”

---

## How does the plugin know a backend secret *changed*?

It re-reads the secret on a timer and compares a SHA256 hash of the value to the hash it stored when the secret was first fetched (`LastHash` on `SecretInfo`).

There is no long-lived Vault event subscription in this path. `startMonitoring` ticks every `ROTATION_INTERVAL` (default 10s), `checkForSecretChanges` fans out goroutines, and `hasSecretChanged` does:

```go
currentValue, err := d.provider.GetSecret(ctx, secretInfo)
currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))
return currentHash != lastHash
```

Why hash instead of storing the raw secret in memory for comparison? You still hold the value briefly during fetch, but the tracker’s durable comparison key is a digest — cheaper to log/compare, and you avoid keeping an extra cleartext copy as the primary “what did we last see?” marker. The tradeoff: every interval you hit the backend again for every tracked secret (mitigated somewhat by parallel checks). If you tighten the interval for faster rotation, you also increase provider QPS.

---

## What is `DoNotReuse` / `secret_reuse`, in plain language?

`DoNotReuse` is a flag in the plugin’s response that tells Docker whether it may cache/reuse a previously fetched secret value. In this project, the compose label `secret_reuse: "true"` means “allow reuse,” which maps to `DoNotReuse: false`.

That double negative trips everyone up once. Docker’s API speaks in “do not reuse.” Operators think in “can this be reused?” `shouldNotReuse` is the translator:

- Label `secret_reuse=true` → allow reuse → return `DoNotReuse=false`
- Otherwise (depending on label/heuristics) → force refetch semantics → `DoNotReuse=true`

You’ll hit this again when a service “doesn’t see” a rotated backend value until recreate: caching behavior and rotation cutover interact. Read `shouldNotReuse` next to `docs/multi-provider.md` when debugging stale values.

---

## Why does the plugin need the Docker socket if it’s already a Docker plugin?

The secrets plugin protocol can only answer `Get`. It cannot create secrets, list services, or update service specs. Rotation needs those Engine API calls, so the plugin mounts `/var/run/docker.sock` and uses `dockerclient.Client`.

Mental model:

| Capability | Mechanism |
|---|---|
| Answer “what is the secret value?” | Plugin protocol via `plugin.sock` |
| Answer “rewrite Swarm to use the new value” | Docker API via docker.sock |

That is why `config.json` lists both the plugin socket interface *and* a bind mount for the Docker socket. A contributor who removes the Docker client “to simplify” would break rotation even if `Get` still worked.

---

## How do Vault/OpenBao paths work here (and why `internal/kvpath`)?

Vault KV v2 does not let you read `secret/myapp/db` the same way you write the logical path in UI docs — the HTTP API inserts a `/data/` segment under the mount. OpenBao follows the same shape. `internal/kvpath` centralizes mount + relative path normalization so each provider doesn’t invent a slightly wrong string.

Example intuition:

- Mount: `secret` (or custom via `VAULT_MOUNT_PATH`)
- Logical secret: `database/mysql`
- API read path something like: `secret/data/database/mysql`

If you hardcode `secret/data/...` while the operator set mount to `kv`, rotation and `Get` both 404. Custom mount support (#127) exists because real Vault installs rarely use only the default.

---

## Where do provider credentials actually come from?

From environment variables set on the **plugin** via `docker plugin set`, declared as settable env in `config.json` — not from the compose service’s env by default.

That distinction matters. Your application container can be free of Vault tokens; the plugin process holds `VAULT_TOKEN` / AWS keys / Azure SP creds / GCP SA JSON. Compose labels on the secret tell the plugin *which* secret to fetch (`vault_path`, etc.); plugin env tells it *how to authenticate* to the backend.

`NewDriver` dumps `os.Environ()` into a settings map and passes that whole map to `provider.Initialize`. Each provider picks the keys it cares about. Adding a new env knob without adding it to `config.json` means `docker plugin set` will reject or ignore it — a common first-contribution footgun.

---

## What is the monitoring package for, if rotation already has logs?

It exposes an operator-facing HTTP surface (dashboard, JSON metrics, health, Prometheus text) about plugin health and rotation counters — separate from secret values themselves.

`monitoring.Monitor` tracks memory/goroutines/GC, rotation success/error counts, and ticker heartbeat. `WebInterface` serves `/`, `/metrics`, `/health`, `/api/metrics`. Metric names still carry a historical `vault_swarm_plugin_*` prefix from when the project was Vault-only — another leftover of the multi-provider evolution, like log lines that still say “Vault Secrets Provider.”

Use it when you want “is the ticker alive?” without SSHing into plugin logs. It is not a substitute for provider audit logs.

---

## How should I add a new provider? (mental checklist)

Implement `SecretsProvider` in a new `providers/<name>.go`, register it in `CreateProvider`, declare env in `config.json`, document labels, and add a smoke test. Do **not** follow the outdated CONTRIBUTING note about a nested `providers/<name>/` package registered in `driver.go` — the live pattern is flat files + `factory.go`.

Minimal shape:

```go
type ContosoProvider struct { /* client fields */ }

func (p *ContosoProvider) Initialize(config map[string]string) error { /* read env, build client */ }
func (p *ContosoProvider) GetSecret(ctx context.Context, info *SecretInfo) ([]byte, error) { /* fetch */ }
func (p *ContosoProvider) SupportsRotation() bool { return true }
func (p *ContosoProvider) GetSecretFieldLabel() string { return "contoso_field" }
func (p *ContosoProvider) BuildSecretPath(req secrets.Request) string { /* from labels */ }
func (p *ContosoProvider) GetProviderName() string { return "contoso" }
func (p *ContosoProvider) Close() error { /* cleanup */ }

// factory.go
case "contoso":
    return &ContosoProvider{}, nil
```

Reuse `providers/common.go` extractors if the backend returns JSON maps with a field name. Prefer a smoke script under `scripts/tests/` over claiming unit-test coverage alone — CI’s real gate is smoke.

---

## What still looks “Vault-shaped” even though the project is multi-provider?

Several strings and metric names. Examples: version log `"Vault Secrets Provider v1.0.0"` in `main.go`, service label `vault.secret.rotated` during rotation, Prometheus prefix `vault_swarm_plugin_*`. Behavior is multi-provider; branding and some identifiers lag. Don’t assume a `vault_` name means the code path only works with Vault — check the `SecretsProvider` call.

---

## Where will these ideas show up again?

| Idea | You’ll see it again when… |
|---|---|
| Plugin socket protocol | Debugging enable/disable, `ServeUnix` name vs `config.json` |
| `SecretInfo` edge translation | Adding labels, fixing path bugs, rotation missing metadata |
| Immutable Swarm secrets | Any rotation failure, orphaned `name-<nano>` secrets |
| Hash polling | Tuning `ROTATION_INTERVAL`, provider rate limits |
| `DoNotReuse` | “Stale secret in task” reports |
| `config.json` settable env | New auth knobs silently not applying |
| Smoke tests | CI red on provider changes that unit tests never touch |

If you only remember one sentence: **Swarm asks `Get`; providers supply bytes; rotation is Swarm cutover driven by hashed re-reads.** Everything else in this repo is machinery around that sentence.
