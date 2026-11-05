#!/usr/bin/env bash
# preflight.sh — lint ports 8080/8081 and cert extensions. Always exits 0.

check_port() {
    local port="$1"
    echo "== Port ${port} =="
    if command -v ss > /dev/null; then
        if ss -ltn 'sport = :'"${port}" | grep -q LISTEN; then
            echo "OCCUPIED"
            ss -ltnp 'sport = :'"${port}"
            echo "Free it with: kill <pid shown above>"
        else
            echo "free"
        fi
    elif command -v lsof > /dev/null; then
        if lsof -i :"${port}" | grep -q LISTEN; then
            echo "OCCUPIED"
            lsof -i :"${port}"
        else
            echo "free"
        fi
    else
        echo "neither ss nor lsof available"
    fi
}

check_ca() {
    echo "== certs/ca.crt =="
    if [ ! -f certs/ca.crt ]; then
        echo "MISSING; run ./make_certs.sh"
        return
    fi
    if openssl x509 -in certs/ca.crt -noout -text 2>&1 | grep -q "X509v3 Key Usage" \
       && openssl x509 -in certs/ca.crt -noout -text 2>&1 | grep -q "Certificate Sign"; then
        echo "OK (keyUsage present)"
    else
        echo "MISSING keyUsage; run ./make_certs.sh"
    fi
}

check_cert() {
    local name="$1"
    local crt="certs/${name}.crt"
    echo "== certs/${name}.crt =="
    [ -f "${crt}" ] || { echo "MISSING; run ./make_certs.sh"; return; }
    if openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "Subject Alternative Name" \
       && openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "TLS Web Server Authentication" \
       && openssl x509 -in "${crt}" -noout -text 2>&1 | grep -q "TLS Web Client Authentication"; then
        echo "OK (SAN + EKU)"
    else
        echo "MISSING SAN or EKU; run ./make_certs.sh"
    fi
}

check_port 8080
check_port 8081
check_ca
check_cert worker
check_cert master
exit 0
