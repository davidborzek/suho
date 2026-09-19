{
  description = "suho — label-driven network policies for plain Docker";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              # rust toolchain (CI: dtolnay/rust-toolchain@stable)
              cargo
              rustc
              rustfmt
              clippy
              rust-analyzer
              cargo-deny
              # rustables' build script runs bindgen
              clang
              libclang
            ];
            # bindgen: where to find libclang.so
            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
            # bindgen: nf_tables.h et al. live outside glibc's headers
            BINDGEN_EXTRA_CLANG_ARGS = "-I${pkgs.linuxHeaders}/include";
          };
        }
      );
    };
}
