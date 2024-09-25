{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
  crypto3,
  ethash,
  intx,
  sszpp,
  valijson,
  gtest,
  evm-assigner,
  proof-producer,
  transpiler,
  parallel-crypto3,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation rec {
  name = "zkevm-framework";

  src = lib.sourceByRegex ./. [ ".*" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [crypto3 evm-assigner proof-producer parallel-crypto3 transpiler intx ethash sszpp valijson gtest];

  cmakeFlags =
  [
      (if runTests then "-DENABLE_TESTS=TRUE" else "")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      "-G Ninja"
  ];

  doBuild = true;
  doCheck = runTests;

  checkPhase = ''
    ctest
    ninja executables_tests
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "zkEVM-framework ${if enableDebug then "debug" else "release"} dev environment activated"
  '';
}
