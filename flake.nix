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
          crypto3 = (pkgs.callPackage ./crypto3.nix {
            runTests = false;
            enableDebug = false;
          });
          crypto3-tests = (pkgs.callPackage ./crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          crypto3-debug-tests = (pkgs.callPackage ./crypto3.nix {
            enableDebug = true;
            runTests = true;
            sanitize = true;
          });
          crypto3-sanitize = (pkgs.callPackage ./crypto3.nix {
            enableDebug = true;
            runTests = true;
            sanitize = true;
          });
          crypto3-clang-debug = (pkgs.callPackage ./crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = false;
            enableDebug = true;
          });

          parallel-crypto3 = (pkgs.callPackage ./parallel-crypto3.nix {
            runTests = false;
            enableDebug = false;
          });
          parallel-crypto3-tests = (pkgs.callPackage ./parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          parallel-crypto3-debug-tests = (pkgs.callPackage ./parallel-crypto3.nix {
            enableDebug = true;
            runTests = true;
          });
          parallel-crypto3-clang-debug = (pkgs.callPackage ./parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
          });

          zkevm-framework = (pkgs.callPackage ./zkevm-framework.nix {
            runTests = false;
            enableDebug = false;
          });
          zkevm-framework-tests = (pkgs.callPackage ./zkevm-framework.nix {
            runTests = true;
            enableDebug = false;
          });
          zkevm-framework-debug-tests = (pkgs.callPackage ./zkevm-framework.nix {
            enableDebug = true;
            runTests = true;
          });
          zkevm-framework-clang-debug = (pkgs.callPackage ./zkevm-framework.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
          });

          proof-producer = (pkgs.callPackage ./proof-producer.nix {
            runTests = false;
            enableDebug = false;
          });
          proof-producer-tests = (pkgs.callPackage ./proof-producer.nix {
            runTests = true;
            enableDebug = false;
          });
          proof-producer-debug-tests = (pkgs.callPackage ./proof-producer.nix {
            enableDebug = true;
            runTests = true;
          });
          proof-producer-clang-debug = (pkgs.callPackage ./proof-producer.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
          });

          debug-tools = (pkgs.callPackage ./debug-tools.nix {
          });

          # The "all" package will build all packages. Convenient for CI,
          # so that "nix build" will check that all packages are correct.
          # The packages that have no changes will not be rebuilt, and instead
          # fetched from the cache.
          all = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3 zkevm-framework proof-producer];
          };
          default = all;
        };

        checks = rec {
          crypto3-gcc = (pkgs.callPackage ./crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          crypto3-clang = (pkgs.callPackage ./crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
          });
          crypto3-clang-sanitize = (pkgs.callPackage ./crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            sanitize = true;
          });

          parallel-crypto3-gcc = (pkgs.callPackage ./parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          parallel-crypto3-clang = (pkgs.callPackage ./parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
          });

          zkevm-framework-gcc = (pkgs.callPackage ./zkevm-framework.nix {
            runTests = true;
            enableDebug = false;
          });

          proof-producer-gcc = (pkgs.callPackage ./proof-producer.nix {
            runTests = true;
            enableDebug = false;
          });
          proof-producer-clang = (pkgs.callPackage ./proof-producer.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
          });

          all-clang = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang parallel-crypto3-clang proof-producer-clang ];
          };
          all-sanitizers = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang-sanitize ];
          };
          all-gcc = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-gcc parallel-crypto3-gcc zkevm-framework-gcc proof-producer-gcc ];
          };
          default = all-gcc;
        };
        apps = {
          assigner = {
            type = "app";
            program = "${self.packages.${system}.zkevm-framework}/bin/assigner";
          };
          multi-threaded = {
            type = "app";
            program = "${self.packages.${system}.proof-producer}/bin/proof-producer-multi-threaded";
          };
        };
      }));
}
