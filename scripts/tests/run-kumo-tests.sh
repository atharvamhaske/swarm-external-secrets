#!/usr/bin/env bash
# Run AWS provider and KMS transformer tests against a local Kumo emulator.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
KUMO_CONTAINER="${KUMO_CONTAINER:-kumo-test}"
KUMO_IMAGE="${KUMO_IMAGE:-ghcr.io/sivchari/kumo:latest}"
KUMO_ENDPOINT="${AWS_ENDPOINT_URL:-http://127.0.0.1:4566}"

export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_ENDPOINT_URL="${KUMO_ENDPOINT}"
export AWS_KMS_ENDPOINT="${AWS_KMS_ENDPOINT:-${KUMO_ENDPOINT}}"

started_container=0

cleanup() {
    if [ "${started_container}" -eq 1 ]; then
        docker stop "${KUMO_CONTAINER}" >/dev/null 2>&1 || true
        docker rm "${KUMO_CONTAINER}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

wait_for_kumo() {
    local elapsed=0
    until curl -sf "${KUMO_ENDPOINT}/" >/dev/null 2>&1; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ "${elapsed}" -ge 30 ]; then
            echo "Kumo did not become ready at ${KUMO_ENDPOINT} within 30s" >&2
            exit 1
        fi
    done
}

if curl -sf "${KUMO_ENDPOINT}/" >/dev/null 2>&1; then
    echo "Using existing Kumo at ${KUMO_ENDPOINT}"
else
    echo "Starting Kumo container ${KUMO_CONTAINER}..."
    docker run -d \
        --name "${KUMO_CONTAINER}" \
        -p 4566:4566 \
        "${KUMO_IMAGE}" >/dev/null
    started_container=1
    wait_for_kumo
    echo "Kumo is ready at ${KUMO_ENDPOINT}"
fi

cd "${REPO_ROOT}"
go test ./providers/... ./internal/secrettransform/... -run Kumo -count=1 -v "$@"
