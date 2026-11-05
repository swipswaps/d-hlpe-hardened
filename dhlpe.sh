#!/usr/bin/env bash
# dhlpe.sh — interactive control panel for D-HLPE v3.1.
#
# Every action validates current state first. No action ever runs a batch
# of unrelated commands. Menu returns to the prompt after each action.
# Paste-safe (no top-level exit); no sed / set -e / exit 1 / 2>/dev/null /
# subprocess.run / rm -rf (rm is used only on specific known files).

_main() {
    local REPO_DIR="${DHLPE_WORK_DIR:-$PWD}"
    cd "${REPO_DIR}" || { echo "cannot cd ${REPO_DIR}"; return 2; }

    local LOG_DIR="${REPO_DIR}/logs"
    mkdir -p "${LOG_DIR}"
    local SECRET="${DHLPE_SECRET:-testsecret}"
    local WORKER_PORT=8081
    local MASTER_PORT=8080
    local LAN_IP
    LAN_IP=$(hostname -I 2>&1 | awk '{print $1}')
    [ -z "${LAN_IP}" ] && LAN_IP="127.0.0.1"

    # ---------------- helpers ----------------

    port_pid() {
        ss -ltnp "sport = :$1" 2>&1 | grep -oP 'pid=\K[0-9]+' | head -1
    }
    is_running() { [ -n "$(port_pid "$1")" ]; }
    worker_pid()  { port_pid "${WORKER_PORT}"; }
    master_pid()  { port_pid "${MASTER_PORT}"; }

    worker_heartbeat_body() {
        curl -sS -X POST "https://localhost:${WORKER_PORT}/heartbeat" \
            --cacert certs/ca.crt \
            --cert certs/master.crt --key certs/master.key \
            --max-time 3 2>&1
    }
    worker_http_code() {
        curl -sS -o /dev/null -w '%{http_code}' -X POST \
            "https://localhost:${WORKER_PORT}/heartbeat" \
            --cacert certs/ca.crt \
            --cert certs/master.crt --key certs/master.key \
            --max-time 3 2>&1
    }

    certs_ok() {
        [ -f certs/ca.crt ] && [ -f certs/worker.crt ] && [ -f certs/master.crt ] && \
        [ -f certs/worker.key ] && [ -f certs/master.key ]
    }

    # ---------------- actions ----------------

    show_status() {
        echo "=== D-HLPE status ==="
        echo "repo:      $(pwd)"
        echo "git HEAD:  $(git rev-parse --short HEAD 2>&1)"
        echo "LAN IP:    ${LAN_IP}"
        echo "secret:    **** (from DHLPE_SECRET or default 'testsecret')"
        echo ""

        echo "certs:"
        if certs_ok; then
            local f exts
            for f in ca worker master; do
                exts=""
                openssl x509 -in "certs/${f}.crt" -noout -text 2>&1 \
                    | grep -q "Subject Alternative Name" && exts="${exts} SAN"
                openssl x509 -in "certs/${f}.crt" -noout -text 2>&1 \
                    | grep -q "TLS Web Server Authentication" && exts="${exts} EKU"
                openssl x509 -in "certs/${f}.crt" -noout -text 2>&1 \
                    | grep -q "X509v3 Key Usage" && exts="${exts} keyUsage"
                echo "  ${f}.crt: present (${exts})"
            done
        else
            echo "  MISSING — run: ./make_certs.sh"
        fi
        echo ""

        local wp
        wp=$(worker_pid)
        echo "worker (port ${WORKER_PORT}):"
        if [ -n "${wp}" ]; then
            echo "  process:   running, PID ${wp}"
            local code
            code=$(worker_http_code)
            if [ "${code}" = "200" ]; then
                echo "  health:    HTTP 200"
                echo "  heartbeat: $(worker_heartbeat_body)"
            else
                echo "  health:    HTTP ${code} (unexpected)"
            fi
        else
            echo "  process:   NOT RUNNING"
        fi
        echo ""

        local mp
        mp=$(master_pid)
        echo "master (port ${MASTER_PORT}):"
        if [ -n "${mp}" ]; then
            echo "  process:   running, PID ${mp}"
        else
            echo "  process:   NOT RUNNING"
        fi
        echo ""

        echo "git push URLs (fan-out):"
        git remote get-url --push --all origin 2>&1 | while read -r u; do
            echo "  ${u}"
        done
    }

    start_worker_bg() {
        if is_running "${WORKER_PORT}"; then
            echo "worker already running on :${WORKER_PORT} (PID $(worker_pid))"
            echo "use option 5 to stop it first"
            return 1
        fi
        if ! certs_ok; then
            echo "certs missing; run ./make_certs.sh first"
            return 1
        fi
        local mdns="${DHLPE_MDNS_NAME:-worker-1}"
        echo "starting worker on :${WORKER_PORT} (mdns ${mdns})"
        nohup python worker_daemon.py \
            --host 0.0.0.0 --port "${WORKER_PORT}" \
            --secret "${SECRET}" \
            --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt \
            --mdns-name "${mdns}" \
            > "${LOG_DIR}/worker.log" 2>&1 &
        local bg=$!
        disown "${bg}" 2>&1 || true
        local waited=0 max_wait=8
        while [ "${waited}" -lt "${max_wait}" ]; do
            if is_running "${WORKER_PORT}"; then
                echo "worker started, PID $(worker_pid), log ${LOG_DIR}/worker.log"
                echo "--- last 5 lines of log ---"
                tail -n 5 "${LOG_DIR}/worker.log"
                return 0
            fi
            if grep -q "ERROR:" "${LOG_DIR}/worker.log" 2>&1; then
                echo "worker FAILED to start:"
                tail -n 30 "${LOG_DIR}/worker.log"
                return 1
            fi
            sleep 1
            waited=$((waited + 1))
        done
        echo "worker FAILED to start after ${max_wait}s:"
        tail -n 30 "${LOG_DIR}/worker.log"
        return 1
    }


    start_master_bg() {
        if is_running "${MASTER_PORT}"; then
            echo "master already running on :${MASTER_PORT} (PID $(master_pid))"
            echo "use option 6 to stop it first"
            return 1
        fi
        if ! certs_ok; then
            echo "certs missing; run ./make_certs.sh first"
            return 1
        fi
        if ! is_running "${WORKER_PORT}"; then
            echo "no worker running on :${WORKER_PORT}"
            echo "start the worker first (option 2), or continue to try anyway"
            printf "continue anyway? [y/N]: "
            read -r ans
            case "${ans}" in
                [yY]*) : ;;
                *) echo "aborted"; return 0 ;;
            esac
        fi
        echo "starting master on :${MASTER_PORT} (--discover, wait up to 10s)"
        nohup python master_node.py \
            --discover --port "${MASTER_PORT}" \
            --secret "${SECRET}" \
            --cert certs/master.crt --key certs/master.key --ca certs/ca.crt \
            > "${LOG_DIR}/master.log" 2>&1 &
        local bg=$!
        disown "${bg}" 2>&1 || true
        local waited=0 max_wait=10
        while [ "${waited}" -lt "${max_wait}" ]; do
            if is_running "${MASTER_PORT}"; then
                echo "master started, PID $(master_pid), log ${LOG_DIR}/master.log"
                echo "--- last 8 lines of log ---"
                tail -n 8 "${LOG_DIR}/master.log"
                return 0
            fi
            if grep -q "ERROR:" "${LOG_DIR}/master.log" 2>&1; then
                echo "master FAILED to start:"
                tail -n 30 "${LOG_DIR}/master.log"
                return 1
            fi
            sleep 1
            waited=$((waited + 1))
        done
        echo "master FAILED to start after ${max_wait}s:"
        tail -n 30 "${LOG_DIR}/master.log"
        return 1
    }


    show_start_commands() {
        echo "Run each command in ITS OWN terminal. Do NOT paste them together."
        echo ""
        echo "--- Terminal A: worker ---"
        echo "cd $(pwd)"
        echo "python worker_daemon.py --host 0.0.0.0 --port ${WORKER_PORT} \\"
        echo "  --secret '${SECRET}' \\"
        echo "  --cert certs/worker.crt --key certs/worker.key --ca certs/ca.crt \\"
        echo "  --mdns-name worker-1"
        echo ""
        echo "--- Terminal B: master (discovered) ---"
        echo "cd $(pwd)"
        echo "python master_node.py --discover --port ${MASTER_PORT} \\"
        echo "  --secret '${SECRET}' \\"
        echo "  --cert certs/master.crt --key certs/master.key --ca certs/ca.crt"
        echo ""
        echo "--- Terminal B (alternative): master (explicit IP) ---"
        echo "python master_node.py --workers ${LAN_IP}:${WORKER_PORT} --port ${MASTER_PORT} \\"
        echo "  --secret '${SECRET}' \\"
        echo "  --cert certs/master.crt --key certs/master.key --ca certs/ca.crt"
        echo ""
        echo "--- Terminal C: smoke test ---"
        echo "cd $(pwd)"
        echo "DHLPE_SECRET='${SECRET}' ./smoke_test.sh"
    }

    stop_by_port() {
        local port=$1 name=$2 pid
        pid=$(port_pid "${port}")
        if [ -z "${pid}" ]; then
            echo "${name}: nothing listening on :${port}"
            return 0
        fi
        echo "${name}: SIGTERM -> PID ${pid}"
        kill -TERM "${pid}"
        local waited=0
        while [ "${waited}" -lt 12 ]; do
            if ! is_running "${port}"; then
                echo "${name}: stopped"
                return 0
            fi
            sleep 1
            waited=$((waited + 1))
        done
        echo "${name}: still running after 12s; SIGKILL"
        kill -KILL "${pid}"
        sleep 1
        if is_running "${port}"; then
            echo "${name}: FAILED to stop (port still bound)"
            return 1
        fi
        echo "${name}: stopped (SIGKILL)"
        return 0
    }

    smoke_test() {
        if ! is_running "${MASTER_PORT}"; then
            echo "master not running on :${MASTER_PORT}; start it first (option 3)"
            return 1
        fi
        if ! is_running "${WORKER_PORT}"; then
            echo "worker not running on :${WORKER_PORT}; start it first (option 2)"
            return 1
        fi
        DHLPE_SECRET="${SECRET}" ./smoke_test.sh
    }

    chat_test() {
        if ! is_running "${MASTER_PORT}"; then
            echo "master not running on :${MASTER_PORT}; start it first (option 3)"
            return 1
        fi
        printf "prompt [Hello!]: "
        local prompt
        read -r prompt
        [ -z "${prompt}" ] && prompt="Hello!"
        local body
        body=$(python3 -c 'import json,sys; print(json.dumps({"model":"local","messages":[{"role":"user","content":sys.argv[1]}],"max_tokens":64}))' "${prompt}")
        echo "sending: ${prompt}"
        curl -sS -X POST "https://localhost:${MASTER_PORT}/v1/chat/completions" \
            -H "Authorization: Bearer ${SECRET}" \
            -H "Content-Type: application/json" \
            -d "${body}" \
            --cacert certs/ca.crt \
            --cert certs/master.crt --key certs/master.key
        echo ""
    }

    rotate_worker_cert() {
        if is_running "${WORKER_PORT}"; then
            echo "worker must be stopped first (option 5)"
            return 1
        fi
        echo "this deletes certs/worker.{crt,key,csr,ext} and regenerates them"
        echo "the CA is preserved, so other nodes trust the new cert without change"
        printf "continue? [y/N]: "
        local ans
        read -r ans
        case "${ans}" in
            [yY]*) : ;;
            *) echo "aborted"; return 0 ;;
        esac
        rm -f certs/worker.crt certs/worker.key certs/worker.csr certs/worker.ext
        ./make_certs.sh
    }

    strict_tls_setup() {
        echo "regenerate certs with LAN IP baked into SAN, then start master with"
        echo "DHLPE_SKIP_HOSTNAME=0 so it verifies the peer certificate name."
        printf "LAN IP [%s]: " "${LAN_IP}"
        local ip
        read -r ip
        [ -z "${ip}" ] && ip="${LAN_IP}"
        DHLPE_EXTRA_SANS="IP:${ip}" ./make_certs.sh
        echo ""
        echo "verify SAN:"
        openssl x509 -in certs/worker.crt -noout -text 2>&1 \
            | grep -A1 "Subject Alternative Name"
        echo ""
        echo "master start command (strict TLS):"
        echo "DHLPE_SKIP_HOSTNAME=0 python master_node.py \\"
        echo "  --workers ${ip}:${WORKER_PORT} --port ${MASTER_PORT} \\"
        echo "  --secret '${SECRET}' \\"
        echo "  --cert certs/master.crt --key certs/master.key --ca certs/ca.crt"
    }

    push_both() {
        echo "git status:"
        git status --short
        echo ""
        printf "commit message (empty to skip commit): "
        local msg
        read -r msg
        if [ -n "${msg}" ]; then
            git add -A
            git commit -m "${msg}"
        fi
        echo ""
        echo "pushing via origin fan-out (both URLs will be attempted):"
        git push origin HEAD
    }

    backup_mirror() {
        if [ -x ./dhlpe-gh-backup.sh ]; then
            ./dhlpe-gh-backup.sh
        else
            echo "dhlpe-gh-backup.sh not present in $(pwd)"
            return 1
        fi
    }

    diagnose() {
        if [ -x ./preflight.sh ]; then
            ./preflight.sh
        else
            echo "preflight.sh not present"
        fi
        echo ""
        if is_running "${WORKER_PORT}"; then
            if [ -f ./diag_probe.py ]; then
                python diag_probe.py --workers "127.0.0.1:${WORKER_PORT}"
            else
                echo "diag_probe.py not present"
            fi
        else
            echo "worker not running; skipping diag_probe"
        fi
    }

    show_usage() {
        cat <<'USAGEEOF'
D-HLPE v3.1 usage summary

  The system is two processes:
    worker_daemon.py on :8081  (mTLS, holds KV cache, mDNS worker-1)
    master_node.py   on :8080  (mTLS, OpenAI-compatible API)

  Start each in its own terminal: menu option 4 prints the exact commands.
  Or use options 2 and 3 to start them in the background with logs.

  curl:
    curl -X POST https://localhost:8080/v1/chat/completions \
      -H "Authorization: Bearer testsecret" \
      -H "Content-Type: application/json" \
      -d '{"model":"local","messages":[{"role":"user","content":"Hi"}],"max_tokens":16}' \
      --cacert certs/ca.crt \
      --cert certs/master.crt --key certs/master.key

  Python (openai SDK):
    import httpx
    from openai import OpenAI
    c = OpenAI(base_url="https://localhost:8080/v1", api_key="testsecret",
               http_client=httpx.Client(verify="certs/ca.crt",
                                       cert=("certs/master.crt","certs/master.key")))
    r = c.chat.completions.create(model="local",
                                  messages=[{"role":"user","content":"Hi"}])
    print(r.choices[0].message.content)

  Stop: menu options 5/6/7, or Ctrl-C in each process terminal.

  Diagnose: menu option 14, or:
    ./preflight.sh
    python diag_probe.py --workers 127.0.0.1:8081

  Recoverable / revertible:
    Option 10 rotates the worker cert without touching the CA.
    Option 11 bakes the LAN IP into every cert SAN and enables strict
    hostname verification (closes M1 in README.txt).
    Option 12 pushes to both GitHub repos; a commit_refs failure on one
    still lands on the other.
    Option 13 refreshes the local bare clone and the GitHub mirror.
USAGEEOF
    }

    # ---------------- menu ----------------

    while true; do
        echo ""
        echo "===== D-HLPE v3.1 control panel ====="
        echo "1)  Show status"
        echo "2)  Start worker in background"
        echo "3)  Start master in background (--discover)"
        echo "4)  Show start commands (run in other terminals)"
        echo "5)  Stop worker"
        echo "6)  Stop master"
        echo "7)  Stop both"
        echo "8)  Smoke test (end-to-end)"
        echo "9)  Chat completion test"
        echo "10) Rotate worker certificate"
        echo "11) Strict TLS setup (bake LAN IP into SAN)"
        echo "12) Commit and push to both GitHub repos"
        echo "13) Refresh backup mirror"
        echo "14) Diagnose (preflight + probe)"
        echo "15) Show usage guide"
        echo "0)  Exit"
        printf "Choice [0-15]: "
        local choice
        read -r choice
        case "${choice}" in
            1)  show_status ;;
            2)  start_worker_bg ;;
            3)  start_master_bg ;;
            4)  show_start_commands ;;
            5)  stop_by_port "${WORKER_PORT}" "worker" ;;
            6)  stop_by_port "${MASTER_PORT}" "master" ;;
            7)  stop_by_port "${WORKER_PORT}" "worker"
                stop_by_port "${MASTER_PORT}" "master" ;;
            8)  smoke_test ;;
            9)  chat_test ;;
            10) rotate_worker_cert ;;
            11) strict_tls_setup ;;
            12) push_both ;;
            13) backup_mirror ;;
            14) diagnose ;;
            15) show_usage ;;
            0)  echo "bye"; return 0 ;;
            "") : ;;
            *)  echo "invalid choice: ${choice}" ;;
        esac
        echo ""
        printf "Press Enter to return to menu..."
        read -r _
    done
}

_main "$@"
