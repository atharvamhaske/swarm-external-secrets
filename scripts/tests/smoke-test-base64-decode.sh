#!/usr/bin/env bash

set -ex

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh disable=SC1091
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
PROVIDER="${1:-${PROVIDER:-vault}}"

case "${PROVIDER}" in
    vault)
        CONTAINER_IMAGE="hashicorp/vault:latest"
        CONTAINER_NAME="smoke-vault-b64"
        DEV_ROOT_TOKEN_ENV="VAULT_DEV_ROOT_TOKEN_ID"
        CLI_BIN="vault"
        CLI_ADDR_ENV="VAULT_ADDR"
        CLI_TOKEN_ENV="VAULT_TOKEN"
        PLUGIN_CONFIG_PREFIX="VAULT"
        LABEL_PATH="vault_path"
        LABEL_FIELD="vault_field"
        ;;
    openbao)
        CONTAINER_IMAGE="quay.io/openbao/openbao:latest"
        CONTAINER_NAME="smoke-openbao-b64"
        DEV_ROOT_TOKEN_ENV="BAO_DEV_ROOT_TOKEN_ID"
        CLI_BIN="bao"
        CLI_ADDR_ENV="BAO_ADDR"
        CLI_TOKEN_ENV="BAO_TOKEN"
        PLUGIN_CONFIG_PREFIX="OPENBAO"
        LABEL_PATH="openbao_path"
        LABEL_FIELD="openbao_field"
        ;;
    *)
        echo "Unsupported provider '${PROVIDER}'. Supported providers: vault, openbao" >&2
        exit 1
        ;;
esac

ROOT_TOKEN="smoke-root-token"
SERVER_ADDR="http://127.0.0.1:8200"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"

STACK_NAME="smoke-${PROVIDER}-b64"
STACK_NAME_INVALID="smoke-${PROVIDER}-b64-inv"
NETWORK_NAME="smoke-network-${PROVIDER}"
NETWORK_NAME_INVALID="smoke-network-inv-${PROVIDER}"
SECRET_PATH="database/credentials"

RAW_VALUE="hello-base64"
BASE64_VALUE="aGVsbG8tYmFzZTY0"
INVALID_VALUE="invalid-base64-payload-not-b64!@#$"

TEST_DIR="$(mktemp -d)"
COMPOSE_FILE_VALID="${TEST_DIR}/compose-valid.yml"
COMPOSE_FILE_INVALID="${TEST_DIR}/compose-invalid.yml"

EXIT_CODE=0

# Cleanup trap
cleanup() {
    local rc=$?
    if [[ "${EXIT_CODE}" -ne 0 ]]; then
        rc="${EXIT_CODE}"
    fi
    echo -e "${RED}Running base64 decode smoke test cleanup for ${PROVIDER}...${DEF}"
    remove_stack "${STACK_NAME_INVALID}" 2>/dev/null || true
    remove_stack "${STACK_NAME}" 2>/dev/null || true
    docker secret rm "${STACK_NAME}_secret_b64_decoded" 2>/dev/null || true
    docker secret rm "${STACK_NAME}_secret_b64_plain" 2>/dev/null || true
    docker secret rm "${STACK_NAME}_secret_b64_ws" 2>/dev/null || true
    docker secret rm "${STACK_NAME_INVALID}_secret_b64_invalid" 2>/dev/null || true
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm   "${CONTAINER_NAME}" 2>/dev/null || true
    remove_plugin
    if [[ -n "${TEST_DIR:-}" && -d "${TEST_DIR}" ]]; then
        rm -rf "${TEST_DIR}"
    fi
    exit "${rc}"
}
trap cleanup EXIT

# verify_secret removes all whitespace. Compare fixture values directly here
# so unexpected spaces cannot hide decoding errors.
assert_secret_value() {
    local secret_name="$1"
    local expected="$2"
    local description="$3"
    local actual

    info "Verifying ${description}..."
    actual=$(docker exec "${APP_CONTAINER_ID}" cat "/run/secrets/${secret_name}") \
        || die "${description} FAIL: could not read ${secret_name}"
    if [[ "${actual}" != "${expected}" ]]; then
        die "${description} FAIL: expected '${expected}', got '${actual}'"
    fi
    success "${description} PASS"
}

# Start dev container
info "Starting ${PROVIDER} dev container..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p 8200:8200 \
    -e "${DEV_ROOT_TOKEN_ENV}=${ROOT_TOKEN}" \
    "${CONTAINER_IMAGE}" server -dev

# Wait for provider to be ready
info "Waiting for ${PROVIDER} to be ready..."
elapsed=0
until docker exec "${CONTAINER_NAME}" \
        "${CLI_BIN}" status -address="${SERVER_ADDR}" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 30 ]] || die "${PROVIDER} did not become ready within 30s."
done
success "${PROVIDER} is ready."

# Apply policy from vault_conf/admin.hcl
info "Applying policy to ${PROVIDER}..."
docker cp "${POLICY_FILE}" "${CONTAINER_NAME}:/tmp/admin.hcl"
docker exec "${CONTAINER_NAME}" \
    env "${CLI_ADDR_ENV}=${SERVER_ADDR}" "${CLI_TOKEN_ENV}=${ROOT_TOKEN}" \
    "${CLI_BIN}" policy write smoke-policy /tmp/admin.hcl
success "Policy applied."

# Write test secrets
info "Writing test secrets to ${PROVIDER}..."
docker exec "${CONTAINER_NAME}" \
    env "${CLI_ADDR_ENV}=${SERVER_ADDR}" "${CLI_TOKEN_ENV}=${ROOT_TOKEN}" \
    "${CLI_BIN}" kv put \
    "secret/${SECRET_PATH}" \
    "payload=${BASE64_VALUE}" \
    "whitespace_payload=  ${BASE64_VALUE}  " \
    "invalid_payload=${INVALID_VALUE}"
success "Secrets written to secret/${SECRET_PATH}."

# Get auth token from provider
info "Getting auth token from ${PROVIDER}..."
AUTH_TOKEN=$(docker exec "${CONTAINER_NAME}" \
    env "${CLI_ADDR_ENV}=${SERVER_ADDR}" "${CLI_TOKEN_ENV}=${ROOT_TOKEN}" \
    "${CLI_BIN}" token create \
        -policy="smoke-policy" \
        -field=token)
success "Got auth token."

# Build plugin and set provider configuration
info "Building plugin and configuring ${PROVIDER} provider..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="${PROVIDER}" \
    "${PLUGIN_CONFIG_PREFIX}_ADDR=${SERVER_ADDR}" \
    "${PLUGIN_CONFIG_PREFIX}_AUTH_METHOD=token" \
    "${PLUGIN_CONFIG_PREFIX}_TOKEN=${AUTH_TOKEN}" \
    "${PLUGIN_CONFIG_PREFIX}_MOUNT_PATH=secret" \
    ENABLE_ROTATION="false" \
    ENABLE_MONITORING="false"
success "Plugin configured with ${PROVIDER} token."

# Enable plugin
info "Enabling plugin..."
enable_plugin

# Write valid test compose file
cat <<EOF > "${COMPOSE_FILE_VALID}"
version: '3.8'

services:
  app:
    image: busybox:latest
    command: >
      sh -c "
        while true; do
          sleep 5
        done
      "
    secrets:
      - secret_b64_decoded
      - secret_b64_plain
      - secret_b64_ws
    deploy:
      replicas: 1
      restart_policy:
        condition: any
    networks:
      - ${NETWORK_NAME}

secrets:
  secret_b64_decoded:
    driver: ${PLUGIN_NAME}
    labels:
      ${LABEL_PATH}: "${SECRET_PATH}"
      ${LABEL_FIELD}: "payload"
      base64_decode: "true"
  secret_b64_plain:
    driver: ${PLUGIN_NAME}
    labels:
      ${LABEL_PATH}: "${SECRET_PATH}"
      ${LABEL_FIELD}: "payload"
      base64_decode: "false"
  secret_b64_ws:
    driver: ${PLUGIN_NAME}
    labels:
      ${LABEL_PATH}: "${SECRET_PATH}"
      ${LABEL_FIELD}: "whitespace_payload"
      base64_decode: "true"

networks:
  ${NETWORK_NAME}:
    driver: overlay
EOF

# Deploy valid swarm stack
info "Deploying valid base64 test stack..."
deploy_stack "${COMPOSE_FILE_VALID}" "${STACK_NAME}" 60

# Retrieve running container ID
info "Retrieving running container ID..."
APP_CONTAINER_ID=$(get_running_container_id "${STACK_NAME}" "app")
[[ -n "${APP_CONTAINER_ID}" ]] || die "Failed to get running container ID for stack '${STACK_NAME}'"

assert_secret_value secret_b64_decoded "${RAW_VALUE}" \
    "Case 1: base64_decode=true delivers decoded bytes"
assert_secret_value secret_b64_plain "${BASE64_VALUE}" \
    "Case 2: base64_decode=false preserves the stored value"
assert_secret_value secret_b64_ws "${RAW_VALUE}" \
    "Whitespace case: surrounding whitespace is trimmed before decoding"

# Clean up valid stack
info "Removing valid test stack..."
remove_stack "${STACK_NAME}"

# Write invalid test compose file
cat <<EOF > "${COMPOSE_FILE_INVALID}"
version: '3.8'

services:
  invalid_app:
    image: busybox:latest
    command: >
      sh -c "
        while true; do
          sleep 5
        done
      "
    secrets:
      - secret_b64_invalid
    deploy:
      replicas: 1
      restart_policy:
        condition: none
    networks:
      - ${NETWORK_NAME_INVALID}

secrets:
  secret_b64_invalid:
    driver: ${PLUGIN_NAME}
    labels:
      ${LABEL_PATH}: "${SECRET_PATH}"
      ${LABEL_FIELD}: "invalid_payload"
      base64_decode: "true"

networks:
  ${NETWORK_NAME_INVALID}:
    driver: overlay
EOF

# Deploy invalid stack to test failure behavior
info "Deploying stack with invalid base64 secret to verify Case 3..."
docker stack deploy -c "${COMPOSE_FILE_INVALID}" "${STACK_NAME_INVALID}"

info "Waiting for service '${STACK_NAME_INVALID}_invalid_app' to fail due to invalid base64..."
elapsed=0
saw_error=0
error_details=""

while [[ "${elapsed}" -lt 60 ]]; do
    task_err=$(docker service ps "${STACK_NAME_INVALID}_invalid_app" --no-trunc --format '{{.Error}}' 2>/dev/null || true)
    daemon_err=$(docker_daemon_logs 2>/dev/null || true)

    if echo "${task_err}" | grep -qi "base64"; then
        saw_error=1
        error_details="${task_err}"
        break
    fi

    if echo "${daemon_err}" | grep -q "failed to base64-decode secret"; then
        saw_error=1
        error_details=$(echo "${daemon_err}" | grep "failed to base64-decode secret" | tail -1)
        break
    fi

    sleep 2
    elapsed=$((elapsed + 2))
done

# Confirm the service container NEVER reached Running state
running_count=$(docker stack ps "${STACK_NAME_INVALID}" \
    --filter "desired-state=running" \
    --format '{{.CurrentState}}' 2>/dev/null \
    | grep -c "Running" || true)

if [[ "${running_count}" -gt 0 ]]; then
    die "Case 3 FAIL: service with invalid base64 unexpectedly reached running state"
fi

if [[ "${saw_error}" -eq 0 ]]; then
    info "Service ps diagnostics:"
    docker service ps "${STACK_NAME_INVALID}_invalid_app" --no-trunc || true
    die "Case 3 FAIL: service did not report base64 decode error within 60s"
fi

# Confirm error output does NOT leak the invalid secret value
combined_error_output="${error_details} $(docker_daemon_logs 2>/dev/null || true)"
if echo "${combined_error_output}" | grep -Fq "${INVALID_VALUE}"; then
    die "Case 3 FAIL: error output leaked secret value '${INVALID_VALUE}'"
fi

success "Case 3 PASS: invalid base64 secret failed clearly without leaking secret value (error: ${error_details})"

# Clean up invalid stack
info "Removing invalid test stack..."
remove_stack "${STACK_NAME_INVALID}"

success "All base64 decode smoke tests PASSED for ${PROVIDER}"
