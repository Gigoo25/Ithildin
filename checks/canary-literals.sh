#!/usr/bin/env bash
set -euo pipefail

# Relative paths make the two exceptions exact, independent of the store path.
cd "${1:?source directory required}"
status=0
hits=$(grep -rEn --exclude-dir=.git '__CANARY_[A-Z]+_[0-9]+__' .) || status=$?
if (( status > 1 )); then
    echo 'Cannot scan source for literal canary placeholders' >&2
    exit "$status"
fi
hits=$(printf '%s\n' "$hits" | grep -vE '^\./home-manager/packages/sensitive-canary/core\.ts:' || true)
if [[ -n "$hits" ]]; then
    printf 'literal canary placeholders in source (never write redactions back):\n%s\n' "$hits" >&2
    exit 1
fi
