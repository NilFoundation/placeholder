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

  # add these, when proof verification start working:
  # "zkevm_bbf_hardhat_minimal_math_zkevm"
  # "zkevm_bbf_hardhat_minimal_math_rw"
  # "zkevm_bbf_hardhat_minimal_math_bytecode"
  test_names = [
    "zkevm_bbf_hardhat_keccak_copy"
    "zkevm_bbf_hardhat_calldatacopy_copy"
    "zkevm_bbf_hardhat_exp_copy"
    "zkevm_bbf_hardhat_exp_rw"
    "zkevm_bbf_hardhat_minimal_math_copy"
    "zkevm_bbf_hardhat_modular_operations_copy"
  ];

  checkPhase = ''
    ./crypto3/libs/blueprint/test/zkevm_bbf/multi_thread_tests/blueprint_zkevm_bbf_multi_thread__hardhat_test -- --proof --run_test=${lib.strings.concatStringsSep "," test_names}
  '';

  dontInstall = true;
  installPhase = "true";

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to verify-proofs environment!"
  '';
}
