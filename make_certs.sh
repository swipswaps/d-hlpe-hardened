#!/usr/bin/env bash
# make_certs.sh — idempotent SAN+EKU+keyUsage mTLS cert generator.
# Citations:
#   [8]  https://github.com/fastapi/fastapi/discussions/7176
#   [19] https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.4
#   [20] https://cabforum.org/2016/01/14/ballot-sc12-deprecate-internal-names/
#   [21] https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12
#   [23] https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
#   [24] https://github.com/elastic/elasticsearch/issues/117769

if ! command -v openssl > /dev/null; then
    echo "openssl not found; install it and re-run ./make_certs.sh"
    exit 0
fi

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"
CERT_DAYS="${DHLPE_CERT_DAYS:-3650}"
EXTRA_SANS="${DHLPE_EXTRA_SANS:-}"
CA_REGENERATED=0

build_sans() {
    local name="$1"
    local sans="DNS:localhost,DNS:${name},DNS:${name}.local,IP:127.0.0.1,IP:::1"
    if [ -n "${EXTRA_SANS}" ]; then
        sans="${sans},${EXTRA_SANS}"
    fi
    printf '%s' "${sans}"
}

ca_has_key_usage() {
    local crt="${CERT_DIR}/ca.crt"
    [ -f "${crt}" ] || return 1
    openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "X509v3 Key Usage" || return 1
    openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "Certificate Sign" || return 1
    return 0
}

needs_regen() {
    local crt="$1"
    if [ ! -f "${crt}" ]; then return 0; fi
    if ! openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "Subject Alternative Name"; then return 0; fi
    if ! openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "TLS Web Server Authentication"; then return 0; fi
    if ! openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "TLS Web Client Authentication"; then return 0; fi
    if [ -n "${EXTRA_SANS}" ]; then
        local _ifs="${IFS}" entry ip host
        IFS=','
        for entry in ${EXTRA_SANS}; do
            case "${entry}" in
                IP:*)
                    ip="${entry#IP:}"
                    IFS="${_ifs}"
                    if ! openssl x509 -in "${crt}" -noout -text 2>&1 | grep -qF "IP Address:${ip}"; then
                        IFS="${_ifs}"; return 0
                    fi
                    IFS=','
                    ;;
                DNS:*)
                    host="${entry#DNS:}"
                    IFS="${_ifs}"
                    if ! openssl x509 -in "${crt}" -noout -text 2>&1 | grep -qF "DNS:${host}"; then
                        IFS="${_ifs}"; return 0
                    fi
                    IFS=','
                    ;;
                *) IFS="${_ifs}"; return 0 ;;
            esac
        done
        IFS="${_ifs}"
    fi
    return 1
}

gen_ca() {
    local need_ca=0
    if [ ! -f "${CERT_DIR}/ca.key" ]; then
        openssl genrsa -out "${CERT_DIR}/ca.key" 4096
        need_ca=1
    fi
    if [ ! -f "${CERT_DIR}/ca.crt" ]; then
        need_ca=1
    elif ! ca_has_key_usage; then
        echo "certs/ca.crt lacks keyUsage; regenerating CA"
        need_ca=1
    fi
    if [ "${need_ca}" -eq 1 ]; then
        openssl req -new -x509 -days "${CERT_DAYS}" \
            -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
            -subj "/CN=D-HLPE-CA" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectKeyIdentifier=hash"
        if [ $? -ne 0 ]; then
            cat > "${CERT_DIR}/ca.cnf" <<'CACNF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = D-HLPE-CA
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
CACNF
            openssl req -new -x509 -days "${CERT_DAYS}" \
                -key "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
                -config "${CERT_DIR}/ca.cnf"
        fi
        CA_REGENERATED=1
        echo "generated certs/ca.crt (keyUsage=keyCertSign,cRLSign)"
    else
        echo "certs/ca.crt already present with keyUsage"
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

    if [ "${CA_REGENERATED}" -eq 0 ] && needs_regen "${crt}"; then
        echo "certs/${name}.crt already present with SAN + EKU"
        return 0
    fi
    if [ -f "${crt}" ]; then
        echo "regenerating certs/${name}.crt (CA regenerated or ext missing)"
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

    printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' \
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
        echo "generated certs/${name}.crt (SAN, EKU, keyUsage)"
    else
        echo "ERROR: failed to generate certs/${name}.crt"
    fi
}

gen_ca
gen_node_cert master
gen_node_cert worker
exit 0
