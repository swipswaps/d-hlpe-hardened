#!/usr/bin/env bash
# build_dhlpe.sh — post-generation helper. Idempotent.
# Citation [12]: https://cli.github.com/manual/gh_repo_create

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "${SCRIPT_DIR}" || { echo "cannot cd ${SCRIPT_DIR}"; return 2; }

if [ -x ./make_certs.sh ]; then
    ./make_certs.sh
fi

git init
git add .
if ! git diff --cached --quiet; then
    git commit -m "D-HLPE v2.2 post-generation refresh"
fi

if ! command -v gh >/dev/null; then
    echo "gh CLI not found; files ready locally in ${SCRIPT_DIR}"
    return 0
fi

if ! gh auth status >/dev/null; then
    echo "gh not authenticated; run 'gh auth login' to enable push"
    return 0
fi

REPO_EXISTS=$(gh repo view d-hlpe-hardened --json name --jq .name || true)
if [ -z "${REPO_EXISTS}" ]; then
    gh repo create d-hlpe-hardened --source . --public --push \
        --description "Hardened Distributed Heterogeneous LLM Pipeline Engine v2.2"
else
    if ! git remote | grep -q '^origin$'; then
        GH_USER=$(gh api user --jq .login || true)
        if [ -n "${GH_USER}" ]; then
            git remote add origin "https://github.com/${GH_USER}/d-hlpe-hardened.git"
        fi
    fi
    git push -u origin HEAD
fi
return 0
