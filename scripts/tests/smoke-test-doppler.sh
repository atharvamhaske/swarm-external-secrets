#!/usr/bin/env bash
# End-to-end smoke test for SECRETS_PROVIDER=doppler against the live Doppler API.
#
# Prerequisite: In your Doppler project + config, create a secret named SMOKE_PLUGIN_TEST
# with value matching DOPPLER_SMOKE_VALUE.
#
# Required env vars:
#   DOPPLER_KEY or DOPPLER_TOKEN — Doppler API token (see https://docs.doppler.com/)
#   DOPPLER_PROJECT — project name
#   DOPPLER_CONFIG — config / environment name (e.g. dev)
#   DOPPLER_SMOKE_VALUE — must match the value of secret SMOKE_PLUGIN_TEST in Doppler
#
# Optional:
#   DOPPLER_SMOKE_VALUE_ROTATED — if set, updates the secret via Doppler API and checks rotation
#
# Go client: https://github.com/dilutedev/doppler
#
# If required vars are missing, exits 0 (skip) so CI does not fail without secrets.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

STACK_NAME="smoke-doppler"
SECRET_NAME="smoke_secret"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-doppler-compose.yml"
DOPPLER_SECRET_KEY="SMOKE_PLUGIN_TEST"

KEY="${DOPPLER_KEY:-${DOPPLER_TOKEN:-}}"

if [ -z "${KEY}" ] || [ -z "${DOPPLER_PROJECT:-}" ] || [ -z "${DOPPLER_CONFIG:-}" ] || [ -z "${DOPPLER_SMOKE_VALUE:-}" ]; then
	info "Skipping Doppler smoke test: set DOPPLER_KEY (or DOPPLER_TOKEN), DOPPLER_PROJECT, DOPPLER_CONFIG, DOPPLER_SMOKE_VALUE"
	info "Create secret '${DOPPLER_SECRET_KEY}' in that project/config with the same value as DOPPLER_SMOKE_VALUE."
	info "Example:"
	info "  export DOPPLER_KEY='dp.st.<token>'  # or DOPPLER_TOKEN"
	info "  export DOPPLER_PROJECT='my-project'"
	info "  export DOPPLER_CONFIG='dev'"
	info "  export DOPPLER_SMOKE_VALUE='value-matching-doppler-secret'"
	info "  ./scripts/tests/smoke-test-doppler.sh"
	exit 0
fi

cleanup() {
	echo -e "${RED}Running Doppler smoke test cleanup...${DEF}"
	remove_stack "${STACK_NAME}" || true
	docker secret rm "${SECRET_NAME}" 2>/dev/null || true
	remove_plugin
}
trap cleanup EXIT

info "Building plugin and configuring Doppler provider..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
	SECRETS_PROVIDER="doppler" \
	DOPPLER_KEY="${KEY}" \
	DOPPLER_PROJECT="${DOPPLER_PROJECT}" \
	DOPPLER_CONFIG="${DOPPLER_CONFIG}" \
	ENABLE_ROTATION="true" \
	ROTATION_INTERVAL="10s" \
	ENABLE_MONITORING="false"
success "Plugin configured for Doppler."

info "Enabling plugin..."
enable_plugin

info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 90

sleep 10
log_stack "${STACK_NAME}" "app"

info "Verifying secret value from Doppler..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${DOPPLER_SMOKE_VALUE}" 90

if [ -n "${DOPPLER_SMOKE_VALUE_ROTATED:-}" ]; then
	info "Updating secret in Doppler via API (rotation check)..."
	# Same endpoint as github.com/dilutedev/doppler UpdateSecret (POST /v3/configs/config/secrets)
	json_body="{\"project\":\"${DOPPLER_PROJECT}\",\"config\":\"${DOPPLER_CONFIG}\",\"secrets\":{\"${DOPPLER_SECRET_KEY}\":\"${DOPPLER_SMOKE_VALUE_ROTATED}\"}}"
	curl -sS -f -X POST "https://api.doppler.com/v3/configs/config/secrets" \
		-H "Authorization: Bearer ${KEY}" \
		-H "Content-Type: application/json" \
		-d "${json_body}" >/dev/null
	success "Doppler secret updated."

	info "Waiting for plugin rotation interval..."
	sleep 15

	log_stack "${STACK_NAME}" "app"
	verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${DOPPLER_SMOKE_VALUE_ROTATED}" 180
fi

success "Doppler smoke test PASSED"
