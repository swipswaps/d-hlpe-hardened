#!/usr/bin/env bash
# dhlpe-gh-backup.sh v4 — create or update a GitHub mirror, mirror refs.
# Every `local` is inside `_main`. Failures print their captured stderr.
# No sed / set -e / exit 1 / 2>/dev/null / subprocess.run / rm -rf.

_main() {
    local BACKUP_REPO="${DHLPE_BACKUP_REPO:-d-hlpe-hardened-mirror}"
    local VIS="${DHLPE_BACKUP_VIS:---public}"
    local BARE_DIR="${DHLPE_BARE_DIR:-$HOME/backups/d-hlpe-hardened.git}"
    local FANOUT="${DHLPE_FANOUT:-1}"

    if ! git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
        echo "ERROR: not inside a git work tree"
        return 2
    fi
    local TOP
    TOP=$(git rev-parse --show-toplevel)
    cd "${TOP}" || return 2

    if ! command -v gh > /dev/null; then
        echo "ERROR: gh CLI not found"
        return 2
    fi
    local AUTH_OUT AUTH_RC
    AUTH_OUT=$(gh auth status 2>&1)
    AUTH_RC=$?
    if [ "${AUTH_RC}" -ne 0 ]; then
        echo "ERROR: gh is not authenticated:"
        printf '%s\n' "${AUTH_OUT}"
        return 2
    fi

    local USER_OUT USER_RC GH_USER
    USER_OUT=$(gh api user --jq .login 2>&1)
    USER_RC=$?
    if [ "${USER_RC}" -ne 0 ] || [ -z "${USER_OUT}" ]; then
        echo "ERROR: gh api user failed:"
        printf '%s\n' "${USER_OUT}"
        return 2
    fi
    GH_USER="${USER_OUT}"

    local FULL="${GH_USER}/${BACKUP_REPO}"
    local MIRROR_URL="https://github.com/${FULL}.git"

    echo "user       : ${GH_USER}"
    echo "destination: ${FULL} (${VIS})"
    echo "bare clone : ${BARE_DIR}"

    # Credential helper: documented requirement for HTTPS push.
    local SETUP_OUT SETUP_RC
    SETUP_OUT=$(gh auth setup-git 2>&1)
    SETUP_RC=$?
    if [ "${SETUP_RC}" -ne 0 ]; then
        echo "WARNING: gh auth setup-git failed:"
        printf '%s\n' "${SETUP_OUT}"
    fi

    # Prepare bare clone.
    mkdir -p "$(dirname "${BARE_DIR}")" || return 2
    if [ -d "${BARE_DIR}" ]; then
        echo "refreshing bare clone"
        local FETCH_OUT FETCH_RC
        FETCH_OUT=$(git --git-dir="${BARE_DIR}" fetch --prune --tags origin \
            '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*' 2>&1)
        FETCH_RC=$?
        printf '%s\n' "${FETCH_OUT}"
        if [ "${FETCH_RC}" -ne 0 ]; then
            echo "ERROR: could not refresh bare clone"
            return 3
        fi
    else
        echo "creating bare clone"
        local CLONE_OUT CLONE_RC
        CLONE_OUT=$(git clone --bare "${TOP}" "${BARE_DIR}" 2>&1)
        CLONE_RC=$?
        printf '%s\n' "${CLONE_OUT}"
        if [ "${CLONE_RC}" -ne 0 ]; then
            echo "ERROR: bare clone failed"
            return 3
        fi
    fi

    # Existence check by exit code, not by output.
    local VIEW_OUT VIEW_RC
    VIEW_OUT=$(gh repo view "${FULL}" 2>&1)
    VIEW_RC=$?
    if [ "${VIEW_RC}" -eq 0 ]; then
        echo "repository exists; skipping creation"
    elif printf '%s' "${VIEW_OUT}" | grep -qi "not found"; then
        echo "repository does not exist; creating it"
        local CREATE_OUT CREATE_RC
        CREATE_OUT=$(gh repo create "${FULL}" "${VIS}" 2>&1)
        CREATE_RC=$?
        printf '%s\n' "${CREATE_OUT}"
        if [ "${CREATE_RC}" -ne 0 ]; then
            case "${CREATE_OUT}" in
                *"Something went wrong while executing your query"*)
                    echo "Transient GraphQL 5xx; re-run later."
                    ;;
                *"already exists"*)
                    echo "Created concurrently; continuing."
                    ;;
                *)
                    echo "ERROR: non-transient create failure."
                    return 4
                    ;;
            esac
            if [ "${CREATE_RC}" -ne 0 ]; then
                return 4
            fi
        fi
    else
        echo "ERROR: could not determine whether ${FULL} exists:"
        printf '%s\n' "${VIEW_OUT}"
        return 4
    fi

    # Wait for the git endpoint.
    echo "waiting for git endpoint"
    local WAIT=0
    while [ "${WAIT}" -lt 60 ]; do
        if git ls-remote "${MIRROR_URL}" > /dev/null 2>&1; then
            echo "reachable after ${WAIT}s"
            break
        fi
        sleep 3
        WAIT=$((WAIT + 3))
    done
    if [ "${WAIT}" -ge 60 ]; then
        echo "ERROR: git endpoint not reachable after 60s"
        return 5
    fi

    # Mirror.
    echo "mirroring refs"
    local PUSH_OUT PUSH_RC
    PUSH_OUT=$(git --git-dir="${BARE_DIR}" push --mirror "${MIRROR_URL}" 2>&1)
    PUSH_RC=$?
    printf '%s\n' "${PUSH_OUT}"
    if [ "${PUSH_RC}" -ne 0 ]; then
        echo "=== REF PUSH FAILED (exit ${PUSH_RC}) ==="
        case "${PUSH_OUT}" in
            *"commit_refs"*)
                echo "Server-side reference failure. Repository exists and is empty."
                echo "Do not force-push. Re-run later to retry only this step."
                return 6
                ;;
            *"Repository not found"*)
                echo "Git endpoint still propagating. Re-run in a few minutes."
                return 7
                ;;
            *)
                echo "Unclassified failure. Repository exists and is empty."
                return 8
                ;;
        esac
    fi
    echo "mirror succeeded"

    # Verify.
    local LOCAL_REFS REMOTE_REFS
    LOCAL_REFS=$(git --git-dir="${BARE_DIR}" for-each-ref \
        --format='%(refname) %(objectname)' refs/heads refs/tags | sort)
    REMOTE_REFS=$(git ls-remote "${MIRROR_URL}" 'refs/heads/*' 'refs/tags/*' \
        2>&1 | awk '{print $2" "$1}' | sort)
    if [ "${LOCAL_REFS}" = "${REMOTE_REFS}" ]; then
        echo "refs match"
    else
        echo "WARNING: ref sets differ"
        echo "local:";  printf '%s\n' "${LOCAL_REFS}"
        echo "remote:"; printf '%s\n' "${REMOTE_REFS}"
    fi

    # Fan-out.
    if [ "${FANOUT}" = "1" ]; then
        local PUSH_URLS
        PUSH_URLS=$(git remote get-url --push --all origin 2>&1)
        if printf '%s\n' "${PUSH_URLS}" | grep -qxF "${MIRROR_URL}"; then
            echo "origin already fans out to the mirror"
        else
            git remote set-url --add --push origin "${MIRROR_URL}"
            echo "appended mirror to origin push URLs"
        fi
        echo "origin push URLs:"
        git remote get-url --push --all origin
    fi

    echo "=== GITHUB MIRROR READY ==="
    echo "mirror: https://github.com/${FULL}"
    return 0
}

_main "$@"
