{ lib,
  stdenv,
  src_repo,
  ninja,
  pkg-config,
  cmake,
  boost183,
  # We'll use boost183 by default, but you can override it
  boost_lib ? boost183,
  gdb,
  crypto3,
  ethash,
  intx,
  sszpp,
  valijson,
  gtest,
  evm-assigner,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation rec {
  name = "zkevm-framework";

  src = src_repo;

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost_lib) else boost_lib) ];

  buildInputs = [crypto3 evm-assigner intx ethash sszpp valijson gtest];

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
