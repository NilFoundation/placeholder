{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
  lldb,
  cmake_modules,
  ethash,
  intx,
  sszpp,
  valijson,
  gtest,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation rec {
  name = "zkevm-framework";

  src = lib.sourceByRegex ./. ["^zkevm-framework(/.*)?$" "^evm-assigner(/.*)?$" "^proof-producer(/.*)?$" "^crypto3(/.*)?$" "^parallel-crypto3(/.*)?$" "CMakeLists.txt"];
  hardeningDisable = [ "fortify" ];

  nativeBuildInputs =[ cmake ninja pkg-config ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules intx ethash sszpp valijson gtest];

  cmakeFlags =
  [
      (if runTests then "-DENABLE_TESTS=TRUE" else "")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      "-DZKEVM_FRAMEWORK_ENABLE=TRUE"
      "-G Ninja"
  ];

  doBuild = true;
  doCheck = runTests;

  checkPhase = ''
    cd zkevm-framework && ctest
    cd .. && ninja executables_tests
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "zkEVM-framework ${if enableDebug then "debug" else "release"} dev environment activated"
  '';
}
