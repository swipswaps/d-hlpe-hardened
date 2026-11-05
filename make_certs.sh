#!/usr/bin/env bash
# make_certs.sh — idempotent mTLS cert generator (standalone subprocess).
# Citation [8]: https://github.com/fastapi/fastapi/discussions/7176
# PATCH [A]: `exit 0` instead of `return 0` — this script is run as a
# subprocess, not sourced, so `return` is a syntax error at file scope.

if ! command -v openssl >/dev/null; then
    echo "openssl not found; install it and re-run ./make_certs.sh"
    exit 0
fi

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"

gen_ca() {
    if [ ! -f "${CERT_DIR}/ca.key" ]; then
        openssl genrsa -out "${CERT_DIR}/ca.key" 4096
    fi
    if [ ! -f "${CERT_DIR}/ca.crt" ]; then
        openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca.key" \
            -out "${CERT_DIR}/ca.crt" -subj "/CN=D-HLPE-CA" \
            -addext "basicConstraints=critical,CA:TRUE"
        if [ $? -ne 0 ]; then
            openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca.key" \
                -out "${CERT_DIR}/ca.crt" -subj "/CN=D-HLPE-CA"
        fi
        echo "generated certs/ca.crt"
    else
        echo "certs/ca.crt already present"
    fi
}

gen_node_cert() {
    local name="$1"
    if [ ! -f "${CERT_DIR}/${name}.key" ]; then
        openssl genrsa -out "${CERT_DIR}/${name}.key" 2048
    fi
    if [ ! -f "${CERT_DIR}/${name}.crt" ]; then
        openssl req -new -key "${CERT_DIR}/${name}.key" \
            -out "${CERT_DIR}/${name}.csr" -subj "/CN=${name}"
        if [ -f "${CERT_DIR}/ca.srl" ]; then
            openssl x509 -req -days 3650 -in "${CERT_DIR}/${name}.csr" \
                -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
                -CAserial "${CERT_DIR}/ca.srl" -out "${CERT_DIR}/${name}.crt"
        else
            openssl x509 -req -days 3650 -in "${CERT_DIR}/${name}.csr" \
                -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
                -CAcreateserial -out "${CERT_DIR}/${name}.crt"
        fi
        echo "generated certs/${name}.crt"
    else
        echo "certs/${name}.crt already present"
    fi
}

gen_ca
gen_node_cert master
gen_node_cert worker
exit 0
