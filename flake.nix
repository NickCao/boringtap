{
  inputs = {
    nixpkgs.url = "github:NickCao/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let pkgs = import nixpkgs { inherit system; }; in
        with pkgs; rec {
          devShells.default = mkShell {
            nativeBuildInputs = [ cargo rustc rust-analyzer rustfmt clippy iperf3 clang-tools ];
            buildInputs = [ liburing ];
          };
        }
      );
}
