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
  enableDebug ? false,
  staticBuild ? false,
  sanitize ? false,
  crypto3_tests ? false
}:
let
  inherit (lib) optional;

  # Aux function that assembles a shell line for running test binary for specific (test suite, test case, circuit subset) combination
  buildTestRunLines = {binary}:
    [ "${binary} -- --proof" ];

in stdenv.mkDerivation rec {
  name = "Proof verifier test";
  pname = "proof-verifier-test";

  src = lib.sourceByRegex ./. [ "^crypto3(/.*)?$" "^parallel-crypto3(/.*)?$" "CMakeLists.txt" ];
  hardeningDisable = [ "fortify" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules];

  cmakeFlags =
    [
      "-DPARALLEL_CRYPTO3_ENABLE=TRUE"
      "-DBUILD_PARALLEL_CRYPTO3_TESTS=TRUE"
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" # to allow VSCode navigation/completion/etc
    "-G Ninja"
  ];

  buildPhase = ''
    ninja blueprint_multi_thread_zkevm_bbf_hardhat_test
  '';

  cmakeBuildType = if enableDebug then "Debug" else "Release";
  doCheck = true;

  test_lines = buildTestRunLines {
    binary = "./parallel-crypto3/libs/parallel-blueprint/test/blueprint_multi_thread_zkevm_bbf_hardhat_test";
  };

  checkPhase = lib.concatLines (["set -x"] ++ test_lines);

  dontInstall = true;
  installPhase = "true";

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to verify-proofs environment!"
  '';
}
