#!/usr/bin/env bash
# Layer 2: prove AWS STS + Secrets Manager work with web identity only (no static keys).
# Supports:
#   - token-file mode (existing JWT file)
#   - direct SPIFFE mode (builds the helper once to fetch a JWT-SVID into a temp file)
#
# Prerequisites:
#   - aws CLI v2
#   - IAM role trust + OIDC (or your test JWT) already configured
#
# Required env:
#   AWS_REGION
#   AWS_ROLE_ARN
# One of:
#   AWS_WEB_IDENTITY_TOKEN_FILE
#   AWS_SPIFFE_JWT_AUDIENCE
# Optional:
#   SPIFFE_ENDPOINT_SOCKET
#   AWS_ROLE_SESSION_NAME (default: swarm-secrets-web-identity-probe)
#   AWS_SM_SECRET_ID (default: database/mysql — must exist in Secrets Manager)
#
# Do NOT set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

SESSION_NAME="${AWS_ROLE_SESSION_NAME:-swarm-secrets-web-identity-probe}"
SECRET_ID="${AWS_SM_SECRET_ID:-database/mysql}"
HELPER_BIN="${TMPDIR:-/tmp}/spiffe-token-helper"
TEMP_TOKEN_FILE=""

if [[ -z "${AWS_REGION:-}" ]] || [[ -z "${AWS_ROLE_ARN:-}" ]]; then
	die "Set AWS_REGION and AWS_ROLE_ARN"
fi

if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] || [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
	die "Unset AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for this probe (web identity only)"
fi

if [[ -n "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ]]; then
	if [[ ! -f "${AWS_WEB_IDENTITY_TOKEN_FILE}" ]] || [[ ! -r "${AWS_WEB_IDENTITY_TOKEN_FILE}" ]]; then
		die "Token file missing or not readable: ${AWS_WEB_IDENTITY_TOKEN_FILE}"
	fi
elif [[ -n "${AWS_SPIFFE_JWT_AUDIENCE:-}" ]]; then
	info "Building SPIFFE token helper for one-shot probe..."
	go build -o "${HELPER_BIN}" ./cmd/spiffe-token-helper
	TEMP_TOKEN_FILE="$(mktemp)"
	AWS_WEB_IDENTITY_TOKEN_FILE="${TEMP_TOKEN_FILE}" \
		AWS_SPIFFE_JWT_AUDIENCE="${AWS_SPIFFE_JWT_AUDIENCE}" \
		SPIFFE_ENDPOINT_SOCKET="${SPIFFE_ENDPOINT_SOCKET:-}" \
		"${HELPER_BIN}" -once
	trap 'rm -f "${TEMP_TOKEN_FILE}" "${HELPER_BIN}"' EXIT
else
	die "Set either AWS_WEB_IDENTITY_TOKEN_FILE or AWS_SPIFFE_JWT_AUDIENCE"
fi

export AWS_REGION
export AWS_ROLE_ARN
export AWS_WEB_IDENTITY_TOKEN_FILE
export AWS_ROLE_SESSION_NAME="${SESSION_NAME}"

info "Probing STS (web identity)..."
aws sts get-caller-identity

info "Probing Secrets Manager GetSecretValue (secret-id=${SECRET_ID})..."
aws secretsmanager get-secret-value \
	--secret-id "${SECRET_ID}" \
	--region "${AWS_REGION}" \
	--query 'SecretString' \
	--output text

success "Web identity probe OK (STS + Secrets Manager)."
