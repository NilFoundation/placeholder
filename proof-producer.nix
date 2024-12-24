{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
  lldb,
  mold,
  protobuf,
  glibc,
  cmake_modules,
  enableDebugging,
  gtest,
  enableDebug ? false,
  staticBuild ? true,
  runTests ? false,
  sanitize? false,
  crypto3_tests? false,
  parallel_crypto3_tets? false,
  crypto3_bechmarks? false,
  parallel_crypto3_bechmarks? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "Proof-producer";
  pname = "proof-producer";

  src = lib.sourceByRegex ./. ["^proof-producer(/.*)?$" "^crypto3(/.*)?$" "^parallel-crypto3(/.*)?$" "CMakeLists.txt"];
  hardeningDisable = [ "fortify" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules gtest protobuf] ++
                  ( lib.optional (staticBuild) glibc.static );

  cmakeFlags =
    [
      "-DCMAKE_INSTALL_PREFIX=${placeholder "out"}"
      (if runTests then "-DENABLE_TESTS=ON" else "-DENABLE_TESTS=OFF")
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      "-DPROOF_PRODUCER_ENABLE=TRUE"
      (if crypto3_tests then "-DBUILD_CRYPTO3_TESTS=TRUE" else "-DBUILD_CRYPTO3_TESTS=False")
      (if parallel_crypto3_tets then "-DBUILD_PARALLEL_CRYPTO3_TESTS=TRUE" else "")
      (if parallel_crypto3_bechmarks then "-DENABLE_BENCHMARKS=ON" else "-DENABLE_BENCHMARKS=OFF")
      (if crypto3_bechmarks then "-DBUILD_CRYPTO3_BENCH_TESTS=ON" else "-DBUILD_CRYPTO3_BENCH_TESTS=OFF")
      (if staticBuild then "-DPROOF_PRODUCER_STATIC_BINARIES=ON" else "-DPROOF_PRODUCER_STATIC_BINARIES=OFF")
      "-G Ninja"
    ];

  cmakeBuildType = if enableDebug then "Debug" else "Release";
  doCheck = runTests;

  checkPhase = ''
    # JUNIT file without explicit file name is generated after the name of the master test suite inside `CMAKE_CURRENT_SOURCE_DIR`
    export BOOST_TEST_LOGGER=JUNIT:HRF
    cd proof-producer
    ctest --verbose --output-on-failure -R
    cd ..
    mkdir -p ${placeholder "out"}/test-logs
    find .. -type f -name '*_test.xml' -exec cp {} ${placeholder "out"}/test-logs \;
    find .. -type f -name '*_benchmark.xml' -exec cp {} ${placeholder "out"}/test-logs \;
  '';

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Proof-producer development environment!"
  '';
}
