{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  crypto3,
  parallel-crypto3,
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
  name = "Proof-producer";

  src = lib.sourceByRegex ./. [ ".*" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules crypto3 parallel-crypto3 ];

  cmakeFlags =
    [
      "-DCMAKE_INSTALL_PREFIX=${placeholder "out"}"
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      "-G Ninja"
    ];

  doCheck = runTests;

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Proof-producer development environment!"
  '';
}
