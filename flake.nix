{
  description = "Ithildin: a redaction engine and the local proxy for model requests";

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
        builtins.filter (file: nixpkgs.lib.hasSuffix ".nix" file) (
          builtins.attrNames (builtins.readDir ./checks)
        )
      );
    in
    {
      packages.${system} = {
        ithildin = pkgs.callPackage ./proxy { };
        default = self.packages.${system}.ithildin;
      };

      checks.${system} =
        nixpkgs.lib.genAttrs checkNames (
          name: nixpkgs.lib.callPackageWith { inherit pkgs root; } (./checks + "/${name}.nix") { }
        )
        // {
          package = self.packages.${system}.ithildin;
        };

      # nixfmt alone reads stdin; `nix fmt` with no arguments formats the repo.
      formatter.${system} = pkgs.writeShellApplication {
        name = "fmt";
        runtimeInputs = [ pkgs.nixfmt ];
        text = ''
          find "''${@:-.}" -name '*.nix' -type f -not -path '*/node_modules/*' -exec nixfmt {} +
        '';
      };
    };
}
