# ithildin: the redaction engine (../engine) as a local
# HTTP proxy in front of model providers (see src/server.ts; entry is src/cli.ts). The engine is
# copied in beside the proxy, matching the `engine` symlink the repo checkout
# uses.
#
# Not `bun build --compile`: the engine reads default-config.json from beside
# its own source at runtime, which a compiled binary's embedded filesystem
# does not provide. A wrapper running bun on the store copy does.
{
  lib,
  stdenvNoCC,
  makeWrapper,
  bun,
}:

let
  engine = ../engine;
in
stdenvNoCC.mkDerivation {
  pname = "ithildin";
  version = "0.1.0";
  src = ./src;

  nativeBuildInputs = [ makeWrapper ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall
    share="$out/share/ithildin"
    mkdir -p "$share/src" "$share/engine/lib"
    cp ${engine}/core.ts "$share/engine/"
    find ${engine}/lib -maxdepth 1 -type f ! -name '*.test.ts' \
      -exec cp {} "$share/engine/lib/" \;
    find "$src" -maxdepth 1 -name '*.ts' ! -name '*.test.ts' ! -name '*.node-check.ts' \
      -exec cp {} "$share/src/" \;
    makeWrapper ${lib.getExe bun} "$out/bin/ithildin" \
      --add-flags "run $share/src/cli.ts"
    runHook postInstall
  '';

  meta = {
    description = "Local proxy that redacts secrets and PII before requests reach model providers";
    mainProgram = "ithildin";
    platforms = lib.platforms.linux;
  };
}
