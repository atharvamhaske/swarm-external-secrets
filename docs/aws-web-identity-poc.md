# AWS Web Identity POC Checklist

This checklist describes two proof-of-concept paths for running one Docker plugin instance per AWS role while keeping the current secret lookup and rotation logic unchanged.

## Goal

Use AWS Secrets Manager with temporary credentials obtained through SPIFFE OIDC web identity instead of static AWS access keys.

## Auth Paths

### 1. Helper to Token File

1. A helper process on the Swarm node fetches a JWT-SVID from SPIRE.
2. The helper writes that JWT to `/run/swarm-external-secrets/aws-web-identity-token`.
3. The Docker plugin mounts `/run/swarm-external-secrets` from the host.
4. The AWS SDK reads `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`.
5. AWS STS exchanges the JWT for temporary credentials.
6. The plugin uses those credentials to read from AWS Secrets Manager.

### 2. Direct Plugin to SPIRE Workload API

1. The Docker plugin mounts `/run/spire/sockets` from the host.
2. The plugin fetches a fresh JWT-SVID directly from the SPIRE Workload API.
3. The plugin passes that JWT to AWS STS using `AssumeRoleWithWebIdentity`.
4. AWS returns temporary credentials.
5. The plugin uses those credentials to read from AWS Secrets Manager.

## POC Checklist

- Create a public SPIRE OIDC discovery endpoint reachable by AWS.
- Run [`scripts/tests/setup-aws-web-identity.sh`](/Users/atharvamhaske/Development/open%20source/swarm-external-secrets/scripts/tests/setup-aws-web-identity.sh) with your admin/SSO credentials to create the OIDC provider, IAM role, and a test secret.
- Create one IAM role per plugin instance or trust boundary.
- Restrict the trust policy by `aud` and `sub`.
- Attach `secretsmanager:GetSecretValue` and optionally `secretsmanager:DescribeSecret`.
- For helper mode, create the host directory: `mkdir -p /run/swarm-external-secrets`.
- For helper mode, run `go run ./cmd/spiffe-token-helper -once` or keep the helper running to refresh `/run/swarm-external-secrets/aws-web-identity-token`.
- For direct mode, make sure the SPIRE agent socket is available at `/run/spire/sockets/agent.sock` on the host.
- Build the plugin on this branch.
- For helper mode, set plugin configuration:

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ROLE_ARN="arn:aws:iam::123456789012:role/swarm-secrets-app1" \
    AWS_WEB_IDENTITY_TOKEN_FILE="/run/swarm-external-secrets/aws-web-identity-token" \
    AWS_ROLE_SESSION_NAME="swarm-external-secrets-app1"
```

- For direct plugin mode, set plugin configuration:

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ROLE_ARN="arn:aws:iam::123456789012:role/swarm-secrets-app1" \
    AWS_SPIFFE_JWT_AUDIENCE="awssm" \
    SPIFFE_ENDPOINT_SOCKET="unix:///run/spire/sockets/agent.sock" \
    AWS_ROLE_SESSION_NAME="swarm-external-secrets-app1"
```

- Enable the plugin.
- Create one AWS Secrets Manager secret.
- Deploy a Swarm service that uses the plugin and confirm the secret resolves.
- Update the secret in AWS and confirm the existing rotation loop picks up the change.
- Run [`scripts/tests/aws-web-identity-probe.sh`](/Users/atharvamhaske/Development/open%20source/swarm-external-secrets/scripts/tests/aws-web-identity-probe.sh) to validate STS + Secrets Manager before involving the plugin.
- Run [`scripts/tests/smoke-test-awssm-web-identity.sh`](/Users/atharvamhaske/Development/open%20source/swarm-external-secrets/scripts/tests/smoke-test-awssm-web-identity.sh) for the real AWS end-to-end smoke test.

## One Plugin Per Role

For multiple AWS identities, install multiple plugin instances with unique names and different role ARNs.

Example:

```bash
docker plugin create aws-secrets-payments:latest ./plugin
docker plugin set aws-secrets-payments:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ROLE_ARN="arn:aws:iam::123456789012:role/payments-secrets" \
    AWS_WEB_IDENTITY_TOKEN_FILE="/run/swarm-external-secrets/aws-web-identity-token"

docker plugin create aws-secrets-analytics:latest ./plugin
docker plugin set aws-secrets-analytics:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ROLE_ARN="arn:aws:iam::123456789012:role/analytics-secrets" \
    AWS_WEB_IDENTITY_TOKEN_FILE="/run/swarm-external-secrets/aws-web-identity-token"
```

Each Swarm secret can then point at the correct plugin instance by driver name.

## Testing in three layers (real AWS, no LocalStack)

Use this order so failures are easy to localize.

### 1) Provider behavior only (LocalStack)

Runs the managed plugin against LocalStack; uses static test keys + `AWS_ENDPOINT_URL`.

```bash
./scripts/tests/smoke-test-awssm.sh
```

This validates secret fetch + rotation in the plugin, **not** OIDC/web identity.

### 2) Web identity only (AWS CLI, no plugin)

On the **same machine** where the token file will live for the plugin:

1. Use **setup credentials** only here (SSO or temporary admin) to create IAM OIDC provider, role trust, and a Secrets Manager secret.
2. Write a JWT to the path you will use in production, e.g.  
   `/run/swarm-external-secrets/aws-web-identity-token` (create the directory on the Docker host; plugin `config.json` mounts that path).
3. **Do not** export `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` for this step.

```bash
export AWS_REGION="us-west-2"
export AWS_ROLE_ARN="arn:aws:iam::123456789012:role/swarm-secrets-poc"
export AWS_WEB_IDENTITY_TOKEN_FILE="/run/swarm-external-secrets/aws-web-identity-token"
export AWS_ROLE_SESSION_NAME="swarm-secrets-poc"
# Optional: export AWS_SM_SECRET_ID="database/mysql"  # default matches smoke compose

./scripts/tests/aws-web-identity-probe.sh
```

You should see `get-caller-identity` return the **assumed role** and `get-secret-value` return your secret string. If this fails, fix IAM/OIDC/token before touching Swarm.

### 3) Plugin end-to-end (real AWS)

1. Create a secret whose name and JSON match `scripts/tests/smoke-awssm-compose.yml` (`aws_secret_name: database/mysql`, `aws_field: password`) or adjust env vars / compose consistently.
2. Set **`AWS_SM_EXPECTED_VALUE`** to the **same** value as the `password` field in that JSON.
3. Run:

```bash
export AWS_REGION="..."
export AWS_ROLE_ARN="..."
export AWS_WEB_IDENTITY_TOKEN_FILE="/run/swarm-external-secrets/aws-web-identity-token"
export AWS_SM_EXPECTED_VALUE="your-password-field-plaintext"
# optional: export AWS_SM_SECRET_ID="database/mysql"
# optional: RUN_PROBE=0 ./scripts/tests/smoke-test-awssm-web-identity.sh   # skip layer-2 if already proven

./scripts/tests/smoke-test-awssm-web-identity.sh
```

The script configures the plugin with **`SECRETS_PROVIDER=aws`** and web identity env vars **only** (no static keys, no `AWS_ENDPOINT_URL`), enables the plugin, deploys the stack, and checks the mounted file.

**Note:** LocalStack is appropriate for layer 1; for federation you should validate layers 2–3 against **real AWS**.
