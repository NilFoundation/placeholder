{
  description = "Placeholder nix file to build all sub-projects";

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
  };

  outputs = { self, nixpkgs, flake-utils, nix-3rdparty, ... }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ nix-3rdparty.overlays.${system}.default ];
        };
      in {
        packages = rec {
          crypto3 = (pkgs.callPackage ./crypto3/crypto3.nix { });
          crypto3-tests = (pkgs.callPackage ./crypto3/crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          crypto3-debug-tests = (pkgs.callPackage ./crypto3/crypto3.nix {
            enableDebug = true;
            runTests = true;
          });
          
          evm-assigner = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            crypto3 = crypto3;
            enableDebug = false;
          });
          evm-assigner-tests = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3;
          });
          evm-assigner-debug-tests = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            enableDebug = true;
            runTests = true;
            crypto3 = crypto3;
          });

          # The "all" package will build all packages. Convenient for CI,
          # so that "nix build" will check that all packages are correct.
          # The packages that have no changes will not be rebuilt, and instead
          # fetched from the cache.
          all = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3 evm-assigner ];
          };
          default = all; 
        };

        checks = rec {
          crypto3-gcc = (pkgs.callPackage ./crypto3/crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          crypto3-clang = (pkgs.callPackage ./crypto3/crypto3.nix {
            stdenv = pkgs.llvmPackages_18.stdenv;
            runTests = true;
            enableDebug = false;
          });

          evm-assigner-gcc = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3-gcc;
          });
          evm-assigner-clang = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            stdenv = pkgs.llvmPackages_18.stdenv;
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3-clang;
          });

          all-clang = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang evm-assigner-clang ];
          };
          all-gcc = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-gcc evm-assigner-gcc ];
          };
          default = all-gcc;
        };
      }));
}
