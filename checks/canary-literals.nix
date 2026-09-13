# Literal __CANARY_*__ placeholders must never land in source: they are
# display-layer redactions, and writing observed output back to disk once
# broke a test with a binding that did not exist. Only the files below may
# contain them (token-format doc examples and the does-not-rescan fixture).
{
  pkgs,
  src,
}:

pkgs.runCommand "check-canary-literals"
  {
    nativeBuildInputs = [
      pkgs.gnugrep
    ];
  }
  ''
    hits=$(grep -rEn '__CANARY_[A-Z]+_[0-9]+__' "$src" || true)
    hits=$(printf '%s\n' "$hits" | grep -v '^$src/home-manager/config/pi/extensions/sensitive-canary/index\.ts:' || true)
    hits=$(printf '%s\n' "$hits" | grep -v '^$src/home-manager/config/pi/extensions/sensitive-canary/index\.test\.ts:' || true)
    if [ -n "$hits" ]; then
      printf 'literal canary placeholders in source (never write redactions back):\n%s\n' "$hits" >&2
      exit 1
    fi
    touch "$out"
  ''
