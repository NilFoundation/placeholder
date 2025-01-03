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
        revCount = self.revCount or self.dirtyRevCount or 1;
        version = "0.0.1-${toString revCount}";
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ nix-3rdparty.overlays.${system}.default ];
        };

        # For proof-producer, our main target is statically linked binaries,
        # so we should pass static libraries as build inputs
        staticOverlay = final: prev: {
          boost = prev.pkgsStatic.boost.override{ enableShared = false;};
          protobuf = (prev.pkgsStatic.protobuf.override { enableShared = false;});
          gtest = (prev.pkgsStatic.gtest.override { static = true;});
        };
        staticPkgs = pkgs.extend staticOverlay;

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
          });
          crypto3-clang-sanitize = (pkgs.callPackage ./crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            sanitize = true;
          });
          crypto3-clang-bench = (pkgs.callPackage ./crypto3.nix {
            runTests = true;
            enableDebug = false;
            benchmarkTests = true;
          });
          crypto3-clang-debug = (pkgs.callPackage ./crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = true;
          });
          crypto3-clang-debug-tests = (pkgs.callPackage ./crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
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
          parallel-crypto3-clang-bench = (pkgs.callPackage ./parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
            benchmarkTests = true;
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

          proof-producer = (staticPkgs.callPackage ./proof-producer.nix {
            runTests = false;
            enableDebug = false;
          });
          proof-producer-tests = (staticPkgs.callPackage ./proof-producer.nix {
            runTests = true;
            enableDebug = false;
          });
          proof-producer-debug-tests = (staticPkgs.callPackage ./proof-producer.nix {
            enableDebug = true;
            runTests = true;
          });
          proof-producer-clang-debug = (staticPkgs.callPackage ./proof-producer.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = false;
          });

          debug-tools = (pkgs.callPackage ./debug-tools.nix {
          });

          develop = (pkgs.callPackage ./proof-producer.nix {
            staticBuild = false;
            enableDebug = true;
            runTests = true;
            sanitize = true;
            crypto3_tests = true;
            parallel_crypto3_tets = true;
            crypto3_bechmarks = true;
            parallel_crypto3_bechmarks = true;
          });

          develop-clang = (pkgs.callPackage ./proof-producer.nix {
            staticBuild = false;
            stdenv = pkgs.llvmPackages_19.stdenv;
            enableDebug = true;
            runTests = true;
            sanitize = true;
            crypto3_tests = true;
            parallel_crypto3_tets = true;
            crypto3_bechmarks = true;
            parallel_crypto3_bechmarks = true;
          });

          # The "all" package will build all packages. Convenient for CI,
          # so that "nix build" will check that all packages are correct.
          # The packages that have no changes will not be rebuilt, and instead
          # fetched from the cache.
          all = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3 parallel-crypto3 proof-producer];
          };
          default = develop;
        };

        checks = rec {
          crypto3-gcc = (pkgs.callPackage ./crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          crypto3-gcc-bench = (pkgs.callPackage ./crypto3.nix {
            runTests = true;
            enableDebug = false;
            benchmarkTests = true;
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
          crypto3-clang-bench = (pkgs.callPackage ./crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            benchmarkTests = true;
          });

          parallel-crypto3-gcc = (pkgs.callPackage ./parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
          });
          parallel-crypto3-gcc-bench = (pkgs.callPackage ./parallel-crypto3.nix {
            runTests = true;
            enableDebug = false;
            benchmarkTests = true;
          });
          parallel-crypto3-clang = (pkgs.callPackage ./parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
          });
          parallel-crypto3-clang-sanitize = (pkgs.callPackage ./parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
          });
          parallel-crypto3-clang-bench = (pkgs.callPackage ./parallel-crypto3.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            benchmarkTests = true;
          });

          proof-producer-gcc = (staticPkgs.callPackage ./proof-producer.nix {
            runTests = true;
            enableDebug = false;
          });
          proof-producer-clang = (staticPkgs.callPackage ./proof-producer.nix {
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
          });
          proof-producer-clang-sanitize = (pkgs.callPackage ./proof-producer.nix {
            staticBuild = false;
            stdenv = pkgs.llvmPackages_19.stdenv;
            runTests = true;
            enableDebug = false;
            sanitize = true;
          });

          all-clang = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang parallel-crypto3-clang proof-producer-clang ];
          };
          all-clang-sanitize = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-clang-sanitize parallel-crypto3-clang-sanitize proof-producer-clang-sanitize ];
          };
          all-gcc = pkgs.symlinkJoin {
            name = "all";
            paths = [ crypto3-gcc parallel-crypto3-gcc proof-producer-gcc ];
          };
          default = all-gcc;
        };
        apps = {
          single-threaded = {
            type = "app";
            program = "${self.packages.${system}.proof-producer}/bin/proof-producer-single-threaded";
          };
          multi-threaded = {
            type = "app";
            program = "${self.packages.${system}.proof-producer}/bin/proof-producer-multi-threaded";
          };
        };
        bundlers = rec {
          deb = pkg:
            pkgs.stdenv.mkDerivation {
              name = "deb-package-${pkg.pname}";
              pname = "deb-package-${pkg.pname}";
              buildInputs = [ pkgs.fpm ];

              unpackPhase = "true";
              buildPhase = ''
                mkdir -p ./usr
                cp -r ${pkg}/bin ./usr/
                chmod -R u+rw,g+r,o+r ./usr
                chmod -R u+rwx,g+rx,o+rx ./usr/bin
                ${pkgs.fpm}/bin/fpm -s dir -t deb --name ${pkg.pname} -v ${version} --deb-use-file-permissions usr
              '';
              installPhase = ''
                mkdir -p $out
                cp -r *.deb $out
              '';
            };
          default = deb;
        };
      }));
}

# To make deb package with proof-producer:
# nix bundle --bundler . .#proof-producer
