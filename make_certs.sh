#!/usr/bin/env bash
# make_certs.sh — idempotent SAN+EKU mTLS cert generator.
# Citations:
#   [8]  https://github.com/fastapi/fastapi/discussions/7176
#   [19] https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.4
#   [20] https://cabforum.org/2016/01/14/ballot-sc12-deprecate-internal-names/
#   [21] https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
# exit 0 at top level (subprocess, not sourced).

if ! command -v openssl > /dev/null; then
    echo "openssl not found; install it and re-run ./make_certs.sh"
    exit 0
fi

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"
CERT_DAYS="${DHLPE_CERT_DAYS:-3650}"
EXTRA_SANS="${DHLPE_EXTRA_SANS:-}"

build_sans() {
    local name="$1"
    local sans="DNS:localhost,DNS:${name},DNS:${name}.local,IP:127.0.0.1,IP:::1"
    if [ -n "${EXTRA_SANS}" ]; then
        sans="${sans},${EXTRA_SANS}"
    fi
    printf '%s' "${sans}"
}

has_san_and_eku() {
    local crt="$1"
    [ -f "${crt}" ] || return 1
    openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "Subject Alternative Name" || return 1
    openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "TLS Web Server Authentication" || return 1
    openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "TLS Web Client Authentication" || return 1
    return 0
}

gen_ca() {
    if [ ! -f "${CERT_DIR}/ca.key" ]; then
        openssl genrsa -out "${CERT_DIR}/ca.key" 4096
    fi
    if [ ! -f "${CERT_DIR}/ca.crt" ]; then
        openssl req -new -x509 -days "${CERT_DAYS}" \
            -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
            -subj "/CN=D-HLPE-CA" \
            -addext "basicConstraints=critical,CA:TRUE"
        if [ $? -ne 0 ]; then
            openssl req -new -x509 -days "${CERT_DAYS}" \
                -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
                -subj "/CN=D-HLPE-CA"
        fi
        echo "generated certs/ca.crt"
    else
        echo "certs/ca.crt already present"
    fi
}

gen_node_cert() {
    local name="$1"
    local key="${CERT_DIR}/${name}.key"
    local csr="${CERT_DIR}/${name}.csr"
    local crt="${CERT_DIR}/${name}.crt"
    local ext="${CERT_DIR}/${name}.ext"
    local sans
    sans="$(build_sans "${name}")"

    if has_san_and_eku "${crt}"; then
        echo "certs/${name}.crt already present with SAN + EKU"
        return 0
    fi
    if [ -f "${crt}" ]; then
        echo "certs/${name}.crt missing SAN or EKU; regenerating"
    fi

    if [ ! -f "${key}" ]; then
        openssl genrsa -out "${key}" 2048
    fi

    openssl req -new -key "${key}" -out "${csr}" \
        -subj "/CN=${name}" \
        -addext "subjectAltName=${sans}"
    if [ $? -ne 0 ]; then
        openssl req -new -key "${key}" -out "${csr}" -subj "/CN=${name}"
    fi

    printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n' \
        "${sans}" > "${ext}"

    if [ -f "${CERT_DIR}/ca.srl" ]; then
        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${csr}" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
            -CAserial "${CERT_DIR}/ca.srl" -out "${crt}" -extfile "${ext}"
    else
        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${csr}" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
            -CAcreateserial -out "${crt}" -extfile "${ext}"
    fi

    if [ -f "${crt}" ]; then
        echo "generated certs/${name}.crt (SAN: ${sans}; EKU: serverAuth+clientAuth)"
    else
        echo "ERROR: failed to generate certs/${name}.crt"
    fi
}

gen_ca
gen_node_cert master
gen_node_cert worker
exit 0
