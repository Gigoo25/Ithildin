# TypeScript is Prettier-formatted (.prettierrc.json), and no line is over
# 100 columns (TigerStyle). Prettier does not break a long string, regex or
# comment, so the column limit is checked on its own.
{
  pkgs,
  root,
  src ? root,
}:

pkgs.runCommand "check-format"
  {
    inherit src;
    # Columns are characters: the ── section rules are 3 bytes each.
    LC_ALL = "C.UTF-8";
    nativeBuildInputs = [
      pkgs.prettier
      pkgs.findutils
      pkgs.gawk
    ];
  }
  ''
    cd "$src"
    prettier --check --log-level warn '**/*.ts'
    long=$(find . -name '*.ts' -not -path '*/node_modules/*' -not -path './proxy/engine/*' \
      -exec awk 'length > 100 { printf "%s:%d: %d columns\n", FILENAME, FNR, length }' {} +)
    if [ -n "$long" ]; then
      printf '%s\n' "$long" >&2
      exit 1
    fi
    touch "$out"
  ''
