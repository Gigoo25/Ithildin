# Unit tests for the engine, apart from the proxy or any agent.
{
  pkgs,
  root,
  src ? root + "/engine",
}:

pkgs.runCommand "check-engine"
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
