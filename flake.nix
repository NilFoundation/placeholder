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
      in rec {
        packages = rec {
          crypto3 = (pkgs.callPackage ./crypto3/crypto3.nix {
            runTests = false;
            enableDebug = false;
          });
          crypto3-tests = (pkgs.callPackage ./crypto3/crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          crypto3-debug-tests = (pkgs.callPackage ./crypto3/crypto3.nix {
            enableDebug = true;
            runTests = true;
          });
          
          parallel-crypto3 = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            runTests = false;
            enableDebug = false;
            crypto3 = crypto3;
          });
          parallel-crypto3-tests = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3;
          });
          parallel-crypto3-debug-tests = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            enableDebug = true;
            runTests = true;
            crypto3 = crypto3;
          });

          evm-assigner = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            runTests = false;
            enableDebug = false;
            crypto3 = crypto3;
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

          zkevm-framework = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            runTests = false;
            enableDebug = false;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
          });
          zkevm-framework-tests = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
          });
          zkevm-framework-debug-tests = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            enableDebug = true;
            runTests = true;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
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

          parallel-crypto3-gcc = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.crypto3;
          });
          parallel-crypto3-clang = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_18.stdenv;
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3-clang;
          });

          evm-assigner-gcc = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.crypto3;
          });
          evm-assigner-clang = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            stdenv = pkgs.llvmPackages_18.stdenv;
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3-clang;
          });

          zkevm-framework-gcc = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.crypto3;
            evm-assigner = evm-assigner-gcc;
          });

          all-clang = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang parallel-crypto3-clang evm-assigner-clang ];
          };
          all-gcc = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-gcc parallel-crypto3-gcc evm-assigner-gcc zkevm-framework-gcc ];
          };
          default = all-gcc;
        };
      }));
}
