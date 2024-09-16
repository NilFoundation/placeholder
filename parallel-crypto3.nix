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
  sanitize? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "Parallel Crypto3";

  src = lib.sourceByRegex ./. ["^crypto3(/.*)?$" "^parallel-crypto3(/.*)?$" "CMakeLists.txt"];
  hardeningDisable = [ "fortify" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules];

  cmakeFlags =
    [
      (if runTests then "-DBUILD_PARALLEL_CRYPTO3_TESTS=TRUE" else "")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      "-DPARALLEL_CRYPTO3_ENABLE=TRUE"
    ];

  doCheck = runTests; # tests are inside parallel-crypto3-tests derivation

  checkPhase = ''
    # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR`
    export BOOST_TEST_LOGGER=JUNIT:HRF
    cd parallel-crypto3
    ctest --verbose --output-on-failure -R
    cd ..
    mkdir -p ${placeholder "out"}/test-logs
    find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Parallel Crypto3 development environment!"
  '';
}
