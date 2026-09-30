# Unit tests for the sensitive-canary engine, apart from any agent.
{
  pkgs,
  root,
  src ? root + "/sensitive-canary",
}:

pkgs.runCommand "check-sensitive-canary"
  {
    nativeBuildInputs = [
      pkgs.bun
      # runtime-inventory-io.test.ts reads remotes from a scratch repo.
      pkgs.git
    ];
  }
  ''
    export HOME="$TMPDIR"
    cp -R ${src} engine
    chmod -R u+w engine
    cd engine
    bun test
    touch "$out"
  ''
