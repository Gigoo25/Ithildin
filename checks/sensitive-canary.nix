# Unit tests for the sensitive-canary engine, apart from any agent.
{
  pkgs,
  src,
}:

pkgs.runCommand "check-sensitive-canary"
  {
    nativeBuildInputs = [ pkgs.bun ];
  }
  ''
    export HOME="$TMPDIR"
    cp -R ${src} engine
    chmod -R u+w engine
    cd engine
    bun test
    touch "$out"
  ''
