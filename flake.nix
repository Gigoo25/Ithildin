{
  description = "sensitive-canary redaction engine and canary-proxy, the local proxy that applies it to model requests";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      root = ./.;
      # Every checks/<name>.nix becomes check <name>, as in the dotfiles flake
      # this repo was split from.
      checkNames = map (file: nixpkgs.lib.removeSuffix ".nix" file) (
        builtins.filter (file: nixpkgs.lib.hasSuffix ".nix" file) (builtins.attrNames (builtins.readDir ./checks))
      );
    in
    {
      packages.${system} = {
        canary-proxy = pkgs.callPackage ./canary-proxy { };
        default = self.packages.${system}.canary-proxy;
      };

      checks.${system} =
        nixpkgs.lib.genAttrs checkNames (
          name: nixpkgs.lib.callPackageWith { inherit pkgs root; } (./checks + "/${name}.nix") { }
        )
        // {
          canary-proxy-package = self.packages.${system}.canary-proxy;
        };

      formatter.${system} = pkgs.nixfmt-rfc-style;
    };
}
