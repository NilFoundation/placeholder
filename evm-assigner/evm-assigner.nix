{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost183,
  # We'll use boost183 by default, but you can override it
  boost_lib ? boost183,
  gdb,
  lldb,
  ethash,
  intx,
  gtest,
  crypto3,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation rec {
  name = "evm-assigner";

  src = lib.sourceByRegex ./. [ ".*" ];
  hardeningDisable = [ "fortify" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost_lib) else boost_lib) ];

  buildInputs = [crypto3 ethash intx gtest];

  cmakeFlags =
  [
      (if runTests then "-DBUILD_TESTS=TRUE" else "")
      (if runTests then "-DBUILD_ASSIGNER_TESTS=TRUE" else "")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      "-G Ninja"
  ];

  doCheck = runTests;

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to evm-assigner development environment!"
  '';
}
