{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
  lldb,
  cmake_modules,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  sanitize ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "Crypto3";

  src = lib.sourceByRegex ./. [ ".*" ];
  hardeningDisable = [ "fortify" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules];

  cmakeFlags =
    [
      (if runTests then "-DBUILD_TESTS=TRUE" else "-DBUILD_TESTS=False")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      "-G Ninja"
    ];

  doCheck = runTests; # tests are inside crypto3-tests derivation

  checkPhase = ''
    # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR`
    export BOOST_TEST_LOGGER=JUNIT:HRF
    ctest --verbose --output-on-failure -R
    mkdir -p ${placeholder "out"}/test-logs
    find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Crypto3 development environment!"
  '';
}
