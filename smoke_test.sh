#!/usr/bin/env bash
# smoke_test.sh — end-to-end mTLS test of worker + master.
#
# All coordinates are configurable via environment variables:
#   DHLPE_MASTER_HOST  (default: localhost)
#   DHLPE_MASTER_PORT  (default: 8080)
#   DHLPE_WORKER_HOST  (default: localhost)
#   DHLPE_WORKER_PORT  (default: 8081)
#   DHLPE_SECRET       (default: testsecret)
#   DHLPE_CERT_DIR     (default: certs)
#
# The previous version hard-coded :8080 and :8081 in the URLs, so
# DHLPE_MASTER_HOST='localhost:8090' produced
#   https://localhost:8090:8080/v1/chat/completions
# which curl rejects with "Port number was not a decimal number".
# Ports are now their own variables; host and port are separate.
#
# Citation: RFC 3986 §3.2.3 (port is a separate URI component from host).
#           https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3

set +e

SECRET="${DHLPE_SECRET:-testsecret}"
CERT_DIR="${DHLPE_CERT_DIR:-certs}"
MASTER_HOST="${DHLPE_MASTER_HOST:-localhost}"
MASTER_PORT="${DHLPE_MASTER_PORT:-8080}"
WORKER_HOST="${DHLPE_WORKER_HOST:-localhost}"
WORKER_PORT="${DHLPE_WORKER_PORT:-8081}"

# Validate ports as decimal integers in the legal range, so a bad env var
# produces a clear message here rather than a confusing curl error later.
case "${MASTER_PORT}" in
    ''|*[!0-9]*) echo "ERROR: DHLPE_MASTER_PORT must be a number, got '${MASTER_PORT}'"; exit 2 ;;
esac
case "${WORKER_PORT}" in
    ''|*[!0-9]*) echo "ERROR: DHLPE_WORKER_PORT must be a number, got '${WORKER_PORT}'"; exit 2 ;;
esac
if [ "${MASTER_PORT}" -lt 1 ] || [ "${MASTER_PORT}" -gt 65535 ]; then
    echo "ERROR: DHLPE_MASTER_PORT out of range: ${MASTER_PORT}"; exit 2
fi
if [ "${WORKER_PORT}" -lt 1 ] || [ "${WORKER_PORT}" -gt 65535 ]; then
    echo "ERROR: DHLPE_WORKER_PORT out of range: ${WORKER_PORT}"; exit 2
fi

echo "== configuration =="
echo "worker : https://${WORKER_HOST}:${WORKER_PORT}"
echo "master : https://${MASTER_HOST}:${MASTER_PORT}"
echo ""

echo "== 1. worker heartbeat =="
curl -sS -X POST "https://${WORKER_HOST}:${WORKER_PORT}/heartbeat" \
    --cacert "${CERT_DIR}/ca.crt" \
    --cert "${CERT_DIR}/master.crt" --key "${CERT_DIR}/master.key"
echo ""

echo "== 2. master chat completion =="
curl -sS -X POST "https://${MASTER_HOST}:${MASTER_PORT}/v1/chat/completions" \
    -H "Authorization: Bearer ${SECRET}" \
    -H "Content-Type: application/json" \
    -d '{"model":"local","messages":[{"role":"user","content":"Hi"}],"max_tokens":16}' \
    --cacert "${CERT_DIR}/ca.crt" \
    --cert "${CERT_DIR}/master.crt" --key "${CERT_DIR}/master.key"
echo ""

exit 0
