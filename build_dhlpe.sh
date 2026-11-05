#!/usr/bin/env bash
# build_dhlpe.sh — post-generation helper. Idempotent.
# Citation [12]: https://cli.github.com/manual/gh_repo_create
# PATCH [A]: exit 0 at top level (subprocess, not sourced).
# PATCH [B]: DHLPE_NO_PUSH=1 short-circuits before any remote work.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "${SCRIPT_DIR}" || { echo "cannot cd ${SCRIPT_DIR}"; exit 2; }

if [ -x ./make_certs.sh ]; then
    ./make_certs.sh
fi

git init
git add .
if ! git diff --cached --quiet; then
    git commit -m "D-HLPE v2.4 post-generation refresh"
fi

if [ "${DHLPE_NO_PUSH:-0}" = "1" ]; then
    echo "DHLPE_NO_PUSH=1; skipping remote push"
    exit 0
fi

if ! command -v gh > /dev/null; then
    echo "gh CLI not found; files ready locally in ${SCRIPT_DIR}"
    exit 0
fi

if ! gh auth status > /dev/null; then
    echo "gh not authenticated; run 'gh auth login' to enable push"
    exit 0
fi

REPO_EXISTS=$(gh repo view d-hlpe-hardened --json name --jq .name || true)
if [ -z "${REPO_EXISTS}" ]; then
    gh repo create d-hlpe-hardened --source . --public --push \
        --description "Hardened Distributed Heterogeneous LLM Pipeline Engine v2.4"
    exit 0
fi

if ! git remote | grep -q '^origin$'; then
    GH_USER=$(gh api user --jq .login || true)
    if [ -n "${GH_USER}" ]; then
        git remote add origin "https://github.com/${GH_USER}/d-hlpe-hardened.git"
    fi
fi

git fetch origin || true
REBASE_OK=0
if git rev-parse --verify origin/master > /dev/null; then
    git rebase origin/master
    if [ $? -ne 0 ]; then
        git rebase --abort || true
    else
        REBASE_OK=1
    fi
fi

if [ $REBASE_OK -eq 1 ]; then
    git push -u origin HEAD
else
    echo "histories unrelated or rebase failed; using --force-with-lease"
    git push --force-with-lease -u origin HEAD
fi
exit 0
