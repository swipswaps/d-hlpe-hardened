#!/usr/bin/env bash
# smoke_test.sh — end-to-end mTLS test of worker (:8081) + master (:8080).
SECRET="${DHLPE_SECRET:-testsecret}"
CERT_DIR="${DHLPE_CERT_DIR:-certs}"
MASTER_HOST="${DHLPE_MASTER_HOST:-localhost}"
WORKER_HOST="${DHLPE_WORKER_HOST:-localhost}"

echo "== 1. worker heartbeat =="
curl -sS -X POST "https://${WORKER_HOST}:8081/heartbeat" \
    --cacert "${CERT_DIR}/ca.crt" \
    --cert "${CERT_DIR}/master.crt" --key "${CERT_DIR}/master.key"
echo ""

echo "== 2. master chat completion =="
curl -sS -X POST "https://${MASTER_HOST}:8080/v1/chat/completions" \
    -H "Authorization: Bearer ${SECRET}" \
    -H "Content-Type: application/json" \
    -d '{"model":"local","messages":[{"role":"user","content":"Hi"}],"max_tokens":16}' \
    --cacert "${CERT_DIR}/ca.crt" \
    --cert "${CERT_DIR}/master.crt" --key "${CERT_DIR}/master.key"
echo ""
exit 0
