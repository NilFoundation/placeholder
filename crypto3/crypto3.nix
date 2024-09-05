{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
  cmake_modules,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "Crypto3";

  src = lib.sourceByRegex ./. [ ".*" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules];

  cmakeFlags =
    [
      (if runTests then "-DBUILD_TESTS=TRUE" else "-DBUILD_TESTS=False")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      "-G Ninja"
    ];

  doCheck = runTests; # tests are inside crypto3-tests derivation

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Crypto3 development environment!"
  '';
}
