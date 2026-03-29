#!/usr/bin/env bash
# End-to-end smoke: AWS Secrets Manager via web identity (real AWS, no LocalStack).
#
# Layer 1 (provider only, LocalStack):  ./scripts/tests/smoke-test-awssm.sh
# Layer 2 (STS + AWS APIs):            ./scripts/tests/aws-web-identity-probe.sh
# Layer 3 (this script): plugin + Swarm stack + file under /run/secrets/
#
# Prerequisites:
#   - Swarm manager (docker swarm init)
#   - Secret in AWS Secrets Manager (same name/field as compose labels)
#   - Token file on host at path the plugin will use (see config.json mount:
#     /run/swarm-external-secrets on host -> /run/swarm-external-secrets in plugin)
#   - Setup IAM / OIDC / role outside this script (use admin credentials or SSO only on your laptop)
#
# Required env:
#   AWS_REGION
#   AWS_ROLE_ARN
#   AWS_SM_EXPECTED_VALUE  (plain string — must match aws_field in the secret JSON)
#
# Optional:
#   AUTH_FLOW=file|direct   (default: file)
#   AWS_WEB_IDENTITY_TOKEN_FILE  (required for file mode unless START_TOKEN_HELPER=1)
#   AWS_SPIFFE_JWT_AUDIENCE      (required for direct mode; optional for helper mode)
#   SPIFFE_ENDPOINT_SOCKET       (required when helper/direct mode needs a non-default socket)
#   AWS_ROLE_SESSION_NAME
#   AWS_SM_SECRET_ID (default: database/mysql — must match compose label aws_secret_name)
#   RUN_PROBE=1 (default) to run aws-web-identity-probe.sh before the plugin; RUN_PROBE=0 to skip
#   START_TOKEN_HELPER=1 to build/run the helper and continuously refresh AWS_WEB_IDENTITY_TOKEN_FILE
#
# Do NOT set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, or AWS_ENDPOINT_URL for the plugin.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

STACK_NAME="${STACK_NAME:-smoke-awssm-wi}"
SECRET_NAME="smoke_secret"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-awssm-compose.yml"
SESSION_NAME="${AWS_ROLE_SESSION_NAME:-swarm-secrets-aws-smoke-wi}"
SECRET_ID="${AWS_SM_SECRET_ID:-database/mysql}"
RUN_PROBE="${RUN_PROBE:-1}"
AUTH_FLOW="${AUTH_FLOW:-file}"
START_TOKEN_HELPER="${START_TOKEN_HELPER:-0}"
HELPER_BIN="${TMPDIR:-/tmp}/spiffe-token-helper"
HELPER_PID=""

if [[ -z "${AWS_REGION:-}" ]] || [[ -z "${AWS_ROLE_ARN:-}" ]]; then
	die "Set AWS_REGION and AWS_ROLE_ARN"
fi

if [[ -z "${AWS_SM_EXPECTED_VALUE:-}" ]]; then
	die "Set AWS_SM_EXPECTED_VALUE to the plaintext value of the aws_field field in the secret (e.g. password)"
fi

case "${AUTH_FLOW}" in
	file)
		:
		;;
	direct)
		[[ -n "${AWS_SPIFFE_JWT_AUDIENCE:-}" ]] || die "Set AWS_SPIFFE_JWT_AUDIENCE for AUTH_FLOW=direct"
		;;
	*)
		die "AUTH_FLOW must be file or direct"
		;;
esac

if [[ "${AUTH_FLOW}" == "file" && "${START_TOKEN_HELPER}" != "1" ]]; then
	if [[ -z "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ]]; then
		die "Set AWS_WEB_IDENTITY_TOKEN_FILE for AUTH_FLOW=file, or use START_TOKEN_HELPER=1"
	fi
	if [[ ! -f "${AWS_WEB_IDENTITY_TOKEN_FILE}" ]] || [[ ! -r "${AWS_WEB_IDENTITY_TOKEN_FILE}" ]]; then
		die "Token file missing or not readable: ${AWS_WEB_IDENTITY_TOKEN_FILE}"
	fi
fi

cleanup() {
	echo -e "${RED}Running AWS web identity smoke cleanup...${DEF}"
	remove_stack "${STACK_NAME}" || true
	docker secret rm "${SECRET_NAME}" 2>/dev/null || true
	remove_plugin
	if [[ -n "${HELPER_PID}" ]]; then
		kill "${HELPER_PID}" 2>/dev/null || true
	fi
	rm -f "${HELPER_BIN}" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "${AUTH_FLOW}" == "file" && "${START_TOKEN_HELPER}" == "1" ]]; then
	[[ -n "${AWS_SPIFFE_JWT_AUDIENCE:-}" ]] || die "Set AWS_SPIFFE_JWT_AUDIENCE when START_TOKEN_HELPER=1"
	AWS_WEB_IDENTITY_TOKEN_FILE="${AWS_WEB_IDENTITY_TOKEN_FILE:-/run/swarm-external-secrets/aws-web-identity-token}"
	info "Building SPIFFE token helper..."
	go build -o "${HELPER_BIN}" ./cmd/spiffe-token-helper
	info "Starting SPIFFE token helper in background..."
	AWS_WEB_IDENTITY_TOKEN_FILE="${AWS_WEB_IDENTITY_TOKEN_FILE}" \
		AWS_SPIFFE_JWT_AUDIENCE="${AWS_SPIFFE_JWT_AUDIENCE}" \
		SPIFFE_ENDPOINT_SOCKET="${SPIFFE_ENDPOINT_SOCKET:-}" \
		"${HELPER_BIN}" &
	HELPER_PID=$!
	sleep 3
fi

if [[ "${RUN_PROBE}" == "1" ]]; then
	info "Running layer-2 probe (STS + GetSecretValue)..."
	AWS_SM_SECRET_ID="${SECRET_ID}" AWS_ROLE_SESSION_NAME="${SESSION_NAME}" \
		AWS_SPIFFE_JWT_AUDIENCE="${AWS_SPIFFE_JWT_AUDIENCE:-}" SPIFFE_ENDPOINT_SOCKET="${SPIFFE_ENDPOINT_SOCKET:-}" \
		"${SCRIPT_DIR}/aws-web-identity-probe.sh"
fi

info "Building plugin (web identity only — no static keys, no endpoint override)..."
build_plugin

if [[ "${AUTH_FLOW}" == "direct" ]]; then
	docker plugin set "${PLUGIN_NAME}" \
		SECRETS_PROVIDER="aws" \
		AWS_REGION="${AWS_REGION}" \
		AWS_ROLE_ARN="${AWS_ROLE_ARN}" \
		AWS_SPIFFE_JWT_AUDIENCE="${AWS_SPIFFE_JWT_AUDIENCE}" \
		SPIFFE_ENDPOINT_SOCKET="${SPIFFE_ENDPOINT_SOCKET:-unix:///run/spire/sockets/agent.sock}" \
		AWS_ROLE_SESSION_NAME="${SESSION_NAME}" \
		ENABLE_ROTATION="true" \
		ROTATION_INTERVAL="30s" \
		ENABLE_MONITORING="false"
else
	docker plugin set "${PLUGIN_NAME}" \
		SECRETS_PROVIDER="aws" \
		AWS_REGION="${AWS_REGION}" \
		AWS_ROLE_ARN="${AWS_ROLE_ARN}" \
		AWS_WEB_IDENTITY_TOKEN_FILE="${AWS_WEB_IDENTITY_TOKEN_FILE}" \
		AWS_ROLE_SESSION_NAME="${SESSION_NAME}" \
		ENABLE_ROTATION="true" \
		ROTATION_INTERVAL="30s" \
		ENABLE_MONITORING="false"
fi

success "Plugin configured (web identity)."

info "Enabling plugin..."
enable_plugin

info "Deploying Swarm stack (${COMPOSE_FILE})..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 120

sleep 10
log_stack "${STACK_NAME}" "app"

info "Verifying mounted secret matches AWS field value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${AWS_SM_EXPECTED_VALUE}" 120

success "AWS web identity smoke test PASSED"
