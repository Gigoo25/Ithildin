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
    # The README too: garble.test.ts reads ../../README.md to assert that a
    # long document of prose survives redaction unchanged. Copying only engine/
    # left it missing, so that check failed on every commit.
    cp -R ${src} engine
    cp ${root}/README.md ./README.md
    chmod -R u+w engine README.md
    cd engine
    bun test
    touch "$out"
  ''
