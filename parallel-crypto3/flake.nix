{
  description =
    "Nix flake for Crypto3 header-only C++ library by Nil; Foundation";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    nix-3rdparty = {
      url = "github:NilFoundation/nix-3rdparty";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    crypto3 = {
      url = "git+https://github.com/NilFoundation/crypto3?submodules=1";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, nix-3rdparty, crypto3, ... }@inputs:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ nix-3rdparty.overlays.${system}.default ];
        };
      in {
        packages = rec {
          parallel-crypto3 = (pkgs.callPackage ./parallel-crypto3.nix {
            src_repo = self;
            crypto3 = crypto3.packages.${system}.crypto3;
          });
          parallel-crypto3-debug = (pkgs.callPackage ./parallel-crypto3.nix {
            src_repo = self;
            crypto3 = crypto3.packages.${system}.crypto3;
            enableDebug = true;
          });
          parallel-crypto3-debug-tests = (pkgs.callPackage ./parallel-crypto3.nix {
            src_repo = self;
            crypto3 = crypto3.packages.${system}.crypto3;
            enableDebug = true;
            runTests = true;
          });
          default = parallel-crypto3;
        };
        checks = rec {
          gcc = (pkgs.callPackage ./parallel-crypto3.nix {
            src_repo = self;
            crypto3 = crypto3.packages.${system}.crypto3;
            runTests = true;
          });
          clang = (pkgs.callPackage ./parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_18.stdenv;
            src_repo = self;
            crypto3 = crypto3.packages.${system}.crypto3;
            runTests = true;
          });
          all = pkgs.symlinkJoin {
            name = "all";
            paths = [ gcc clang ];
          };
          default = all;
        };
      }));
}

# `nix flake -L check` to run all tests (-L to output build logs)
# `nix flake show` to show derivations tree
# If build fails due to OOM, run `export NIX_CONFIG="cores = 2"` to set desired parallel level
