#!/usr/bin/env bash
_main() {
    cd "${DHLPE_WORK_DIR:-$PWD}" || return 2
    if [ ! -f make_certs.sh ]; then echo "make_certs.sh not found"; return 2; fi
    python3 - <<'PYEOF'
import re
with open("make_certs.sh", "r", encoding="utf-8") as f:
    src = f.read()
new_fn = '''needs_regen() {
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
}'''
src = re.sub(r"^has_san_and_eku\(\) \{.*?^}", new_fn, src, flags=re.DOTALL | re.MULTILINE)
src = src.replace('has_san_and_eku "${crt}"', 'needs_regen "${crt}"')
with open("make_certs.sh", "w", encoding="utf-8") as f:
    f.write(src)
print("make_certs.sh updated")
PYEOF
    if grep -q '^has_san_and_eku' make_certs.sh; then
        echo "ERROR: old function still present"
        return 3
    fi
    if ! grep -q '^needs_regen()' make_certs.sh; then
        echo "ERROR: new function missing"
        return 3
    fi
    echo "OK: make_certs.sh now checks EXTRA_SANS entries"
    return 0
}
_main "$@"
