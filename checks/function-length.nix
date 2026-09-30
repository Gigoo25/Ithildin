# No function outside the tests is over 70 lines (checks/function-length.ts).
# nixpkgs' typescript is the Go port, which has no JS parser API, so the
# TypeScript 5 package comes from the registry.
{
  pkgs,
  root,
  src ? root,
}:

let
  typescript = pkgs.fetchzip {
    url = "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz";
    hash = "sha256-+jyGI1cbmKZ4gP0TwJul0ktrIFvDbpuu6XmC3mwv2QM=";
  };
in
pkgs.runCommand "check-function-length"
  {
    nativeBuildInputs = [ pkgs.bun ];
    TYPESCRIPT = typescript;
  }
  ''
    export HOME="$TMPDIR"
    bun ${src}/checks/function-length.ts ${src}
    touch "$out"
  ''
