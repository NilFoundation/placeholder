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
  benchmarkTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "Crypto3";

  src = lib.sourceByRegex ./. ["^crypto3(/.*)?$" "CMakeLists.txt"];
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
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      (if benchmarkTests then "-DBUILD_CRYPTO3_BENCH_TESTS=ON" else "-DBUILD_CRYPTO3_BENCH_TESTS=OFF")
      "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" # to allow VSCode navigation/completion/etc
      "-DCMAKE_CXX_STANDARD=23"
      "-DCMAKE_CXX_STANDARD_REQUIRED=ON"
      "-G Ninja"
    ];

  cmakeBuildType = if enableDebug then "Debug" else "Release";
  doCheck = runTests; # tests are inside crypto3-tests derivation

  checkPhase = ''
    # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR`
    export BOOST_TEST_LOGGER=JUNIT:HRF
    cd crypto3
    ctest --verbose --output-on-failure | tee test_errors.txt
    cd ..
    mkdir -p ${placeholder "out"}/test-logs
    find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
    cp crypto3/test_errors.txt ${placeholder "out"}/test-logs \
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Crypto3 development environment!"
  '';
}
