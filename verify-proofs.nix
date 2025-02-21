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
      "-DBUILD_CRYPTO3_TESTS=TRUE"
      "-DPARALLEL_CRYPTO3_ENABLE=TRUE"
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" # to allow VSCode navigation/completion/etc
      "-G Ninja"
    ];

  buildPhase = ''
    ninja blueprint_zkevm_bbf_multi_thread__hardhat_test
  '';

  cmakeBuildType = if enableDebug then "Debug" else "Release";
  doCheck = true;

  test_lines = buildTestRunLines {
    binary = "./crypto3/libs/blueprint/test/zkevm_bbf/multi_thread_tests/blueprint_zkevm_bbf_multi_thread__hardhat_test";

    test_suite = "zkevm_bbf_hardhat";

    test_runs = {
      # test case name
      keccak = [
        "copy" # circuit name (leave empty to run all circuits)
      ];

      calldatacopy = [ "copy" ];

      exp = [ "copy" "rw" ];

      # add these, when proof verification start working:
      # "zkevm_bbf_hardhat/minimal_math zkevm"
      # "zkevm_bbf_hardhat/minimal_math rw"
      # "zkevm_bbf_hardhat/minimal_math bytecode"
      minimal_math = [ "copy" ];

      modular_operations = [ "copy" ];
    };
  };

  checkPhase = lib.concatLines (["set -x"] ++ test_lines);

  dontInstall = true;
  installPhase = "true";

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to verify-proofs environment!"
  '';
}
