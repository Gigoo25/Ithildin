# Unit tests for the proxy, run against the engine it ships with, plus the
# engine's redaction-quality gates driven through the proxy's request path:
# the Node budget and safety checks (production V8, not Bun's node:vm) and the
# synthetic bench (bench/README.md).
{
  pkgs,
  root,
  src ? root + "/proxy",
  engine ? root + "/engine",
}:

pkgs.runCommand "check-proxy"
  {
    nativeBuildInputs = [
      pkgs.bun
      pkgs.nodejs
    ];
  }
  ''
    export HOME="$TMPDIR"
    mkdir proxy
    cp -R ${src}/src ${src}/bench ${src}/bunfig.toml ${src}/test-setup.ts proxy/
    cp -R ${engine} proxy/engine
    chmod -R u+w proxy
    cd proxy
    bun test src bench
    node --test --test-timeout=10000 src/budget.node-check.ts src/safety.node-check.ts
    node bench/run.ts --check > ./bench.json
    touch "$out"
  ''
