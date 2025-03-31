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
  buildTestRunLines = {binary, test_suite, test_runs}:
    builtins.map
      (test_name: "${binary} --run_test=${test_suite}/${test_name} -- --proof --run-for-circuits=${lib.strings.concatStringsSep "," test_runs.${test_name}}\n")
      (builtins.attrNames test_runs)
  ;

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

    test_suite = "zkevm_bbf_hardhat";

    test_runs = {

      # test case name
      keccak = [
        "copy" # circuit name (leave empty to run all circuits)
        "keccak"
        "exp"
        "rw"
        "bytecode"
        "zkevm"
      ];

      minimal_math = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];

      call_counter = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];

      delegatecall_counter = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];

      indexed_log = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak" ];

      cold_sstore = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];

      try_catch = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];
    };
  };

  wide_test_lines = buildTestRunLines {
    binary = "./parallel-crypto3/libs/parallel-blueprint/test/blueprint_multi_thread_zkevm_bbf_zkevm_wide_test";

    test_suite = "zkevm_bbf_wide";

    test_runs = {
      minimal_math = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];
      call_keccak = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];
    };
  };

  checkPhase = lib.concatLines (["set -x"] ++ test_lines ++ wide_test_lines);

  dontInstall = true;
  installPhase = "true";

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to verify-proofs environment!"
  '';
}