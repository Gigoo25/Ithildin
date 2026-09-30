# Literal __ITHILDIN_*__ placeholders must never land in source: they are
# display-layer redactions, and writing observed output back to disk once
# broke a test with a binding that did not exist. Only the files below may
# contain them (token-format doc examples and the does-not-rescan fixture).
{
  pkgs,
  root,
  src ? root,
}:

pkgs.runCommand "check-placeholder-literals"
  {
    inherit src;
    nativeBuildInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.gnugrep
    ];
  }
  ''
    bash ${./placeholder-literals.test.sh} ${./placeholder-literals.sh}
    bash ${./placeholder-literals.sh} "$src"
    touch "$out"
  ''
