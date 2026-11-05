#!/usr/bin/env bash
# make_certs.sh — idempotent SAN-aware mTLS cert generator (standalone).
# Citations:
#   [8]  https://github.com/fastapi/fastapi/discussions/7176
#   [19] https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.4
#   [20] https://cabforum.org/2016/01/14/ballot-sc12-deprecate-internal-names/
# PATCH [A]: exit 0 (this file runs as subprocess, not sourced).
# PATCH [B]: emit Subject Alternative Names so curl / httpx / browsers accept.
# PATCH [C]: regenerate legacy certs that lack SAN. The CA is preserved.

if ! command -v openssl > /dev/null; then
    echo "openssl not found; install it and re-run ./make_certs.sh"
    exit 0
fi

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"

# Certificate lifetime (days). Override via env.
CERT_DAYS="${DHLPE_CERT_DAYS:-3650}"

# Extra SANs supplied by the user for real LAN deployment, e.g.:
#   DHLPE_EXTRA_SANS="IP:192.168.4.50,IP:192.168.4.51,DNS:pi.local"
EXTRA_SANS="${DHLPE_EXTRA_SANS:-}"

build_sans() {
    # $1 = node name (worker or master)
    local name="$1"
    local sans="DNS:localhost,DNS:${name},DNS:${name}.local,IP:127.0.0.1,IP:::1"
    if [ -n "${EXTRA_SANS}" ]; then
        sans="${sans},${EXTRA_SANS}"
    fi
    printf '%s' "${sans}"
}

has_san() {
    # $1 = path to cert. Return 0 if SAN extension present, 1 otherwise.
    if [ ! -f "$1" ]; then
        return 1
    fi
    openssl x509 -in "$1" -noout -text 2>&1 | grep -q "Subject Alternative Name"
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
            # Older OpenSSL (LibreSSL on macOS) lacks -addext.
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

    if has_san "${crt}"; then
        echo "certs/${name}.crt already present with SAN"
        return 0
    fi
    if [ -f "${crt}" ]; then
        echo "certs/${name}.crt lacks Subject Alternative Name; regenerating"
    fi

    if [ ! -f "${key}" ]; then
        openssl genrsa -out "${key}" 2048
    fi

    # CSR with SAN extension. -addext available in OpenSSL 1.1.1+.
    openssl req -new -key "${key}" -out "${csr}" \
        -subj "/CN=${name}" \
        -addext "subjectAltName=${sans}"
    if [ $? -ne 0 ]; then
        # Fallback for older openssl: CSR without extensions.
        openssl req -new -key "${key}" -out "${csr}" -subj "/CN=${name}"
    fi

    # Extension file used by x509 -req; the SAN comes from here.
    printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "${sans}" > "${ext}"

    if [ -f "${CERT_DIR}/ca.srl" ]; then
        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${csr}" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
            -CAserial "${CERT_DIR}/ca.srl" -out "${crt}" \
            -extfile "${ext}"
    else
        openssl x509 -req -days "${CERT_DAYS}" \
            -in "${csr}" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
            -CAcreateserial -out "${crt}" \
            -extfile "${ext}"
    fi

    if [ -f "${crt}" ]; then
        echo "generated certs/${name}.crt (SAN: ${sans})"
    else
        echo "ERROR: failed to generate certs/${name}.crt"
    fi
}

gen_ca
gen_node_cert master
gen_node_cert worker
exit 0
