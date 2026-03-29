#!/usr/bin/env bash
# Idempotent-ish setup helper for real AWS OIDC federation testing.
# Uses your local admin/SSO credentials only to create IAM resources.

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
require_env AWS_OIDC_CLIENT_ID
require_env AWS_OIDC_THUMBPRINT
require_env AWS_ROLE_NAME
require_env SPIFFE_SUBJECT

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
SECRET_ID="${AWS_SM_SECRET_ID:-database/mysql}"
SECRET_JSON="${AWS_SM_SECRET_JSON:-{\"password\":\"awssm-smoke-pass-v1\"}}"
SESSION_POLICY_NAME="${AWS_INLINE_POLICY_NAME:-${AWS_ROLE_NAME}-secretsmanager}"
OIDC_HOSTPATH="${AWS_OIDC_PROVIDER_URL#https://}"
OIDC_PROVIDER_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_HOSTPATH}"

info "Ensuring OIDC provider exists: ${OIDC_PROVIDER_ARN}"
if ! aws iam get-open-id-connect-provider \
	--open-id-connect-provider-arn "${OIDC_PROVIDER_ARN}" >/dev/null 2>&1; then
	aws iam create-open-id-connect-provider \
		--url "${AWS_OIDC_PROVIDER_URL}" \
		--client-id-list "${AWS_OIDC_CLIENT_ID}" \
		--thumbprint-list "${AWS_OIDC_THUMBPRINT}" >/dev/null
fi

TRUST_DOC="$(mktemp)"
POLICY_DOC="$(mktemp)"
trap 'rm -f "${TRUST_DOC}" "${POLICY_DOC}"' EXIT

cat >"${TRUST_DOC}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "${OIDC_PROVIDER_ARN}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_HOSTPATH}:aud": "${AWS_OIDC_CLIENT_ID}",
          "${OIDC_HOSTPATH}:sub": "${SPIFFE_SUBJECT}"
        }
      }
    }
  ]
}
EOF

if aws iam get-role --role-name "${AWS_ROLE_NAME}" >/dev/null 2>&1; then
	info "Updating trust policy on role ${AWS_ROLE_NAME}"
	aws iam update-assume-role-policy \
		--role-name "${AWS_ROLE_NAME}" \
		--policy-document "file://${TRUST_DOC}" >/dev/null
else
	info "Creating role ${AWS_ROLE_NAME}"
	aws iam create-role \
		--role-name "${AWS_ROLE_NAME}" \
		--assume-role-policy-document "file://${TRUST_DOC}" >/dev/null
fi

cat >"${POLICY_DOC}" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "*"
    }
  ]
}
EOF

info "Applying inline Secrets Manager policy to ${AWS_ROLE_NAME}"
aws iam put-role-policy \
	--role-name "${AWS_ROLE_NAME}" \
	--policy-name "${SESSION_POLICY_NAME}" \
	--policy-document "file://${POLICY_DOC}" >/dev/null

info "Ensuring test secret exists in Secrets Manager"
if aws secretsmanager describe-secret --region "${AWS_REGION}" --secret-id "${SECRET_ID}" >/dev/null 2>&1; then
	aws secretsmanager put-secret-value \
		--region "${AWS_REGION}" \
		--secret-id "${SECRET_ID}" \
		--secret-string "${SECRET_JSON}" >/dev/null
else
	aws secretsmanager create-secret \
		--region "${AWS_REGION}" \
		--name "${SECRET_ID}" \
		--secret-string "${SECRET_JSON}" >/dev/null
fi

success "AWS OIDC + role + test secret setup complete."
echo "OIDC provider ARN: ${OIDC_PROVIDER_ARN}"
echo "Role ARN: arn:aws:iam::${AWS_ACCOUNT_ID}:role/${AWS_ROLE_NAME}"
