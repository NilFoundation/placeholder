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
          crypto3-sanitize = (pkgs.callPackage ./crypto3/crypto3.nix {
            enableDebug = true;
            runTests = true;
            sanitize = true;
          });
          crypto3-clang-debug = (pkgs.callPackage ./crypto3/crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = false;
            enableDebug = true;
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
          parallel-crypto3-clang-debug = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
            crypto3 = crypto3-clang-debug;
          });

          evm-assigner = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            runTests = false;
            enableDebug = false;
            crypto3 = parallel-crypto3;
          });
          evm-assigner-tests = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = parallel-crypto3;
          });
          evm-assigner-debug-tests = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            enableDebug = true;
            runTests = true;
            crypto3 = parallel-crypto3;
          });
          evm-assigner-clang-debug = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
            crypto3 = parallel-crypto3-clang-debug;
          });

          zkevm-framework = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            runTests = false;
            enableDebug = false;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
            proof-producer = proof-producer;
            parallel-crypto3 = parallel-crypto3;
          });
          zkevm-framework-tests = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
            proof-producer = proof-producer;
            parallel-crypto3 = parallel-crypto3;
          });
          zkevm-framework-debug-tests = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            enableDebug = true;
            runTests = true;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
            proof-producer = proof-producer;
            parallel-crypto3 = parallel-crypto3;
          });
          zkevm-framework-clang-debug = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
            crypto3 = crypto3-clang-debug;
            evm-assigner = evm-assigner-clang-debug;
            proof-producer = proof-producer-clang-debug;
            parallel-crypto3 = parallel-crypto3-clang-debug;
          });

          proof-producer = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            runTests = false;
            enableDebug = false;
            crypto3 = parallel-crypto3;
          });
          proof-producer-singlethreaded = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            runTests = false;
            enableDebug = false;
            crypto3 = crypto3;
          });
          proof-producer-tests = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = parallel-crypto3;
          });
          proof-producer-debug-tests = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            enableDebug = true;
            runTests = true;
            crypto3 = parallel-crypto3;
          });
          proof-producer-singlethreaded-debug-tests = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            enableDebug = true;
            runTests = true;
            crypto3 = crypto3;
          });
          proof-producer-clang-debug = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
            crypto3 = parallel-crypto3-clang-debug;
          });

          debug-tools = (pkgs.callPackage ./debug-tools/debug-tools.nix {
            crypto3 = crypto3;
          });

          # The "all" package will build all packages. Convenient for CI,
          # so that "nix build" will check that all packages are correct.
          # The packages that have no changes will not be rebuilt, and instead
          # fetched from the cache.
          all = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3 evm-assigner zkevm-framework proof-producer];
          };
          default = all;
        };

        checks = rec {
          crypto3-gcc = (pkgs.callPackage ./crypto3/crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          crypto3-clang = (pkgs.callPackage ./crypto3/crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
          });
          crypto3-clang-sanitize = (pkgs.callPackage ./crypto3/crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            sanitize = true;
          });

          parallel-crypto3-gcc = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.crypto3;
          });
          parallel-crypto3-clang = (pkgs.callPackage ./parallel-crypto3/parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3-clang;
          });

          evm-assigner-gcc = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.parallel-crypto3;
          });
          evm-assigner-clang = (pkgs.callPackage ./evm-assigner/evm-assigner.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            crypto3 = parallel-crypto3-clang;
          });

          zkevm-framework-gcc = (pkgs.callPackage ./zkevm-framework/zkevm-framework.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.crypto3;
            evm-assigner = evm-assigner-gcc;
            proof-producer = proof-producer-gcc;
            parallel-crypto3 = packages.parallel-crypto3;
          });

          proof-producer-gcc = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.parallel-crypto3;
          });
          proof-producer-clang = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            crypto3 = parallel-crypto3-clang;
          });
          proof-producer-singlethreaded-gcc = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            runTests = true;
            enableDebug = false;
            crypto3 = packages.crypto3;
          });
          proof-producer-singlethreaded-clang = (pkgs.callPackage ./proof-producer/proof-producer.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            crypto3 = crypto3-clang;
          });

          all-clang = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang parallel-crypto3-clang evm-assigner-clang proof-producer-clang proof-producer-singlethreaded-clang ];
          };
          all-sanitizers = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang-sanitize ];
          };
          all-gcc = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-gcc parallel-crypto3-gcc evm-assigner-gcc zkevm-framework-gcc proof-producer-gcc proof-producer-singlethreaded-gcc ];
          };
          default = all-gcc;
        };
        apps = {
          assigner = {
            type = "app";
            program = "${self.packages.${system}.zkevm-framework}/bin/assigner";
          };
          single-threaded = {
            type = "app";
            program = "${self.packages.${system}.proof-producer-singlethreaded}/bin/proof-producer-single-threaded";
          };
          multi-threaded = {
            type = "app";
            program = "${self.packages.${system}.proof-producer}/bin/proof-producer-multi-threaded";
          };
        };
      }));
}
