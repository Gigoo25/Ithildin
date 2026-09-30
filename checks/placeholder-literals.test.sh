#!/usr/bin/env bash
set -euo pipefail
checker=$(realpath "${1:?checker path required}")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
src="$work/source with spaces"
allowed="$src/engine"
mkdir -p "$allowed"
printf 'clean\n' > "$src/clean.ts"
bash "$checker" "$src"

# Construct a fixture, not a literal that would fail the repository check.
printf '__ITHILDIN_%s_%s__\n' HOST 9999 > "$allowed/core.ts"
bash "$checker" "$src"

expect_failure() {
    if bash "$checker" "$1" > "$work/output" 2>&1; then
        echo 'checker unexpectedly accepted an invalid source' >&2
        exit 1
    fi
}
cp "$allowed/core.ts" "$src/disallowed.ts"
expect_failure "$src"
grep -q 'disallowed.ts:' "$work/output"
rm "$src/disallowed.ts"
cp "$allowed/core.ts" "$allowed/core.ts.backup"
expect_failure "$src"
rm "$allowed/core.ts.backup"
expect_failure "$work/missing"

# A grep operational error must not be treated as an empty result.
mkdir "$work/bin"
printf '#!/usr/bin/env bash\nexit 2\n' > "$work/bin/grep"
chmod +x "$work/bin/grep"
PATH="$work/bin:$PATH" expect_failure "$src"
echo 'placeholder literal regression checks passed'
