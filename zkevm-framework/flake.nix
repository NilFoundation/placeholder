{
  description = "Nix flake for zkEVM framework";

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
    nil-evm-assigner = {
      type = "github";
      owner = "NilFoundation";
      repo = "evm-assigner";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        nix-3rdparty.follows = "nix-3rdparty";
        nil-crypto3.follows = "nil-crypto3";
      };
    };
    nil-crypto3 = {
      type = "github";
      owner = "NilFoundation";
      repo = "crypto3";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        nix-3rdparty.follows = "nix-3rdparty";
      };
    };
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , nix-3rdparty
    , nil-evm-assigner
    , nil-crypto3
  }:
    (flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        stdenv = pkgs.stdenv;
        crypto3 = nil-crypto3.packages.${system}.crypto3;
        evm-assigner = nil-evm-assigner.packages.${system}.default;
        intx = nix-3rdparty.packages.${system}.intx;
        sszpp = nix-3rdparty.packages.${system}.sszpp;
        
      in rec {
        packages = rec {
          zkevm-framework = (pkgs.callPackage ./zkevm-framework.nix {
            src_repo = self;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
            intx = intx;
            sszpp = sszpp;
          });
          zkevm-framework-debug = (pkgs.callPackage ./zkevm-framework.nix {
            src_repo = self;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
            intx = intx;
            sszpp = sszpp;
            enableDebug = true;
          });
          zkevm-framework-debug-tests = (pkgs.callPackage ./zkevm-framework.nix {
            src_repo = self;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
            intx = intx;
            sszpp = sszpp;
            enableDebug = true;
            runTests = true;
          });
          default = zkevm-framework;
        };
        checks = rec {
          gcc = (pkgs.callPackage ./zkevm-framework.nix {
            src_repo = self;
            crypto3 = crypto3;
            evm-assigner = evm-assigner;
            intx = intx;
            sszpp = sszpp;
            runTests = true;
          });
          default = gcc;
        };
      apps = rec {
        assigner = {
          type = "app";
          program = "${packages.default}/bin/assigner";
        };
      };
    }));
}

# `nix flake -L check` to run all tests (-L to output build logs)
# `nix flake show` to show derivations tree
# If build fails due to OOM, run `export NIX_CONFIG="cores = 2"` to set desired parallel level
