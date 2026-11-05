#!/usr/bin/env bash
# build_dhlpe.sh — post-generation helper. Idempotent. Subprocess (exit 0).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "${SCRIPT_DIR}" || { echo "cannot cd ${SCRIPT_DIR}"; exit 2; }
[ -x ./make_certs.sh ] && ./make_certs.sh
git init
git add .
if ! git diff --cached --quiet; then
    git commit -m "D-HLPE v2.7 post-generation refresh"
fi
[ "${DHLPE_NO_PUSH:-0}" = "1" ] && { echo "DHLPE_NO_PUSH=1"; exit 0; }
command -v gh > /dev/null || { echo "gh not found"; exit 0; }
gh auth status > /dev/null || { echo "gh not authenticated"; exit 0; }
REPO_EXISTS=$(gh repo view d-hlpe-hardened --json name --jq .name || true)
if [ -z "${REPO_EXISTS}" ]; then
    gh repo create d-hlpe-hardened --source . --public --push \
        --description "Hardened Distributed Heterogeneous LLM Pipeline Engine v2.7"
    exit 0
fi
if ! git remote | grep -q '^origin$'; then
    GH_USER=$(gh api user --jq .login || true)
    [ -n "${GH_USER}" ] && git remote add origin "https://github.com/${GH_USER}/d-hlpe-hardened.git"
fi
git fetch origin || true
REBASE_OK=0
if git rev-parse --verify origin/master > /dev/null; then
    git rebase origin/master
    if [ $? -ne 0 ]; then git rebase --abort || true; else REBASE_OK=1; fi
fi
if [ $REBASE_OK -eq 1 ]; then git push -u origin HEAD; else
    echo "force-with-lease"; git push --force-with-lease -u origin HEAD
fi
exit 0
