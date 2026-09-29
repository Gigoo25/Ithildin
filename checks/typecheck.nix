# Strict tsc over the engine, the proxy and the bench (tsconfig.json).
# Type definitions come from the registry tarballs pinned in bun.lock; the
# build fails if bun.lock moves to other versions without this list following.
{
  pkgs,
  root,
  src ? root,
}:

let
  # name, version, sha512 integrity: copied from bun.lock.
  types = [
    {
      name = "@types/bun";
      version = "1.4.2";
      integrity = "sha512-GimotNn7+ZV0uVArItBbriZsR1oNf0+WTzPkdcFrzShI7k2norL0uzEaJT8T33dWr7O/c9ZDuAFQrctKCi72oQ==";
    }
    {
      name = "@types/node";
      version = "26.6.3";
      integrity = "sha512-dsqMQQoeTLqu9wynDD00q573mNzso3IdQOAfHRJqLCcmCFPoGo9A1bDpUcv/9tnKpErQWv9uKeGfl37EIS02Yg==";
    }
    {
      name = "bun-types";
      version = "1.4.2";
      integrity = "sha512-bxV1FgK7yBIzjRe5zBozIM4Bem11ZJcCXSrjWRG3YWLt8yFDePu4cLjpebO8OvPeIE9trbyPF4fuj3Cia4Fj3w==";
    }
    {
      name = "undici-types";
      version = "8.9.0";
      integrity = "sha512-KTDyRTYX8sWmKXAikPHHSyc63CRPETMctyjKFupcC6OBLXT3xsN0e9aF7m+mIXutFWpUXuedtowG7iLOzp0kQg==";
    }
  ];
  tarball =
    pkg:
    pkgs.fetchurl {
      url = "https://registry.npmjs.org/${pkg.name}/-/${baseNameOf pkg.name}-${pkg.version}.tgz";
      hash = pkg.integrity;
    };
  install = pkg: ''
    grep -qF '"${pkg.name}@${pkg.version}", "", ' bun.lock
    grep -qF '"${pkg.integrity}"' bun.lock
    mkdir -p "node_modules/${pkg.name}"
    tar -xzf ${tarball pkg} -C "node_modules/${pkg.name}" --strip-components=1
  '';
in
pkgs.runCommand "check-typecheck"
  {
    nativeBuildInputs = [ pkgs.typescript ];
  }
  ''
    cp -R ${src} repo
    chmod -R u+w repo
    cd repo
    test "$(grep -c '"sha512-' bun.lock)" -eq ${toString (builtins.length types)}
    ${pkgs.lib.concatMapStrings install types}
    tsc -p . --pretty false
    touch "$out"
  ''
