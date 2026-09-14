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
    inherit src;
    nativeBuildInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.gnugrep
    ];
  }
  ''
    bash ${./canary-literals.test.sh} ${./canary-literals.sh}
    bash ${./canary-literals.sh} "$src"
    touch "$out"
  ''
