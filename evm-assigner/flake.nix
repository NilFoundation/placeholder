{
  description = "Nix flake for evm-assigner";

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
    nil-crypto3 = {
      url = "https://github.com/NilFoundation/crypto3";
      type = "git";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        nix-3rdparty.follows = "nix-3rdparty";
      };
    };
  };

  outputs = { self, nixpkgs, nil-crypto3, flake-utils, nix-3rdparty }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        stdenv = pkgs.llvmPackages_16.stdenv;
        crypto3 = nil-crypto3.packages.${system}.crypto3;
        intx = nix-3rdparty.packages.${system}.intx;

      in {
        packages = rec {
          evm-assigner = (pkgs.callPackage ./evm-assigner.nix {
            src_repo = self;
            crypto3 = crypto3;
            intx = intx;
          });
          evm-assigner-debug = (pkgs.callPackage ./evm-assigner.nix {
            src_repo = self;
            crypto3 = crypto3;
            intx = intx;
            enableDebug = true;
          });
          evm-assigner-debug-tests = (pkgs.callPackage ./evm-assigner.nix {
            src_repo = self;
            crypto3 = crypto3;
            intx = intx;
            enableDebug = true;
            runTests = true;
          });
          default = evm-assigner-debug-tests;
        };
        checks = rec {
          gcc = (pkgs.callPackage ./evm-assigner.nix {
            src_repo = self;
            crypto3 = crypto3;
            intx = intx;
            runTests = true;
          });
          clang = (pkgs.callPackage ./evm-assigner.nix {
            stdenv = pkgs.llvmPackages_18.stdenv;
            src_repo = self;
            crypto3 = crypto3;
            intx = intx;
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
