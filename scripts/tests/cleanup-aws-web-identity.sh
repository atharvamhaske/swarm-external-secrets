#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

require_env() {
	local key="$1"
	if [[ -z "${!key:-}" ]]; then
		die "Set ${key}"
	fi
}

require_env AWS_REGION
require_env AWS_OIDC_PROVIDER_URL
require_env AWS_ROLE_NAME

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
SECRET_ID="${AWS_SM_SECRET_ID:-database/mysql}"
SESSION_POLICY_NAME="${AWS_INLINE_POLICY_NAME:-${AWS_ROLE_NAME}-secretsmanager}"
OIDC_HOSTPATH="${AWS_OIDC_PROVIDER_URL#https://}"
OIDC_PROVIDER_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_HOSTPATH}"

info "Removing test secret if present"
aws secretsmanager delete-secret \
	--region "${AWS_REGION}" \
	--secret-id "${SECRET_ID}" \
	--force-delete-without-recovery >/dev/null 2>&1 || true

info "Removing inline policy and role if present"
aws iam delete-role-policy \
	--role-name "${AWS_ROLE_NAME}" \
	--policy-name "${SESSION_POLICY_NAME}" >/dev/null 2>&1 || true
aws iam delete-role \
	--role-name "${AWS_ROLE_NAME}" >/dev/null 2>&1 || true

info "Removing OIDC provider if present"
aws iam delete-open-id-connect-provider \
	--open-id-connect-provider-arn "${OIDC_PROVIDER_ARN}" >/dev/null 2>&1 || true

success "AWS web identity cleanup complete."
