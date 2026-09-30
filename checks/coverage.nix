# Coverage floors (checks/coverage.ts) over the proxy and engine suites run
# together, the way the proxy ships the engine. The suites themselves are
# gated by the proxy and engine checks; this one fails only
# on the numbers.
{
  pkgs,
  root,
  src ? root + "/proxy",
  engine ? root + "/engine",
  script ? root + "/checks/coverage.ts",
}:

pkgs.runCommand "check-coverage"
  {
    nativeBuildInputs = [
      pkgs.bun
      # runtime-inventory-io.test.ts reads remotes from a scratch repo.
      pkgs.git
    ];
  }
  ''
    export HOME="$TMPDIR"
    mkdir proxy
    cp -R ${src}/src ${src}/bench ${src}/bunfig.toml ${src}/test-setup.ts proxy/
    cp -R ${engine} proxy/engine
    chmod -R u+w proxy
    cd proxy
    bun test src bench engine --coverage --coverage-reporter=lcov
    bun ${script} coverage/lcov.info
    touch "$out"
  ''
