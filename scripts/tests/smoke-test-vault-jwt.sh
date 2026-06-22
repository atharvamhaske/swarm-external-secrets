#!/usr/bin/env bash

set -ex

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

VAULT_CONTAINER="smoke-vault-jwt"
VAULT_ROOT_TOKEN="smoke-root-token"
VAULT_ADDR="http://127.0.0.1:8200"
STACK_NAME="smoke-vault-jwt"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="vault-jwt-smoke-pass-v1"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-vault-compose.yml"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"
JWT_WORKDIR="$(mktemp -d)"
JWT_ROLE="swarm-external-secrets"
EXIT_CODE=0

base64url() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

generate_local_jwt() {
    openssl genrsa -out "${JWT_WORKDIR}/jwt-private.pem" 2048 >/dev/null 2>&1
    openssl rsa -in "${JWT_WORKDIR}/jwt-private.pem" -pubout -out "${JWT_WORKDIR}/jwt-public.pem" >/dev/null 2>&1

    local header payload unsigned signature
    header="$(printf '{"alg":"RS256","typ":"JWT"}' | base64url)"
    payload="$(printf '{"iss":"swarm-external-secrets-local","sub":"swarm-external-secrets","aud":"vault"}' | base64url)"
    unsigned="${header}.${payload}"
    signature="$(printf '%s' "${unsigned}" | openssl dgst -sha256 -sign "${JWT_WORKDIR}/jwt-private.pem" -binary | base64url)"
    printf '%s.%s\n' "${unsigned}" "${signature}" > "${JWT_WORKDIR}/workload.jwt"
}

cleanup() {
    echo -e "${RED}Running Vault JWT smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    docker stop "${VAULT_CONTAINER}" 2>/dev/null || true
    docker rm   "${VAULT_CONTAINER}" 2>/dev/null || true
    rm -rf "${JWT_WORKDIR}"
    remove_plugin
    exit "${EXIT_CODE}"
}
trap cleanup EXIT

info "Starting HashiCorp Vault dev container..."
docker run -d \
    --name "${VAULT_CONTAINER}" \
    -p 8200:8200 \
    -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_ROOT_TOKEN}" \
    hashicorp/vault:latest server -dev

info "Waiting for Vault to be ready..."
elapsed=0
until docker exec "${VAULT_CONTAINER}" vault status -address="${VAULT_ADDR}" &>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 30 ]] || die "Vault did not become ready within 30s."
done
success "Vault is ready."

info "Applying policy to Vault..."
docker cp "${POLICY_FILE}" "${VAULT_CONTAINER}:/tmp/admin.hcl"
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault policy write smoke-policy /tmp/admin.hcl
success "Policy applied."

info "Writing test secret to Vault..."
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE}"
success "Secret written."

info "Generating local JWT signing keys and signed JWT..."
generate_local_jwt
docker cp "${JWT_WORKDIR}/jwt-public.pem" "${VAULT_CONTAINER}:/tmp/jwt-public.pem"

info "Configuring Vault JWT auth..."
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault auth enable jwt
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault write auth/jwt/config \
        jwt_validation_pubkeys=@/tmp/jwt-public.pem \
        bound_issuer="swarm-external-secrets-local"
docker exec "${VAULT_CONTAINER}" \
    env VAULT_ADDR="${VAULT_ADDR}" VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault write "auth/jwt/role/${JWT_ROLE}" \
        role_type="jwt" \
        user_claim="sub" \
        bound_audiences="vault" \
        bound_subject="swarm-external-secrets" \
        policies="smoke-policy" \
        ttl="15m"
success "Vault JWT auth configured."

WORKLOAD_JWT="$(tr -d '\n' < "${JWT_WORKDIR}/workload.jwt")"

info "Building plugin and configuring JWT auth..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="${VAULT_ADDR}" \
    VAULT_AUTH_METHOD="jwt" \
    VAULT_JWT_ROLE="${JWT_ROLE}" \
    VAULT_JWT="${WORKLOAD_JWT}" \
    VAULT_JWT_AUTH_PATH="jwt" \
    VAULT_MOUNT_PATH="secret" \
    ENABLE_ROTATION="false" \
    ENABLE_MONITORING="false"
success "Plugin configured with Vault JWT auth."

info "Enabling plugin..."
enable_plugin

info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

success "Vault JWT smoke test PASSED"
