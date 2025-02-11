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
  crypto3_tests ? false,
  proof-producer
}:
let
  inherit (lib) optional;
in stdenv.mkDerivation rec {
  name = "Proof verifier test";
  pname = "proof-verifier-test";

  src = lib.sourceByRegex ./. [ "^crypto3(/.*)?$" "CMakeLists.txt" ];
  hardeningDisable = [ "fortify" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules protobuf] ++
                  ( lib.optional (staticBuild) glibc.static );

  cmakeFlags =
    [
      "-DBUILD_CRYPTO3_TESTS=TRUE"
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" # to allow VSCode navigation/completion/etc
      "-G Ninja"
    ];

  buildPhase = ''
    ninja blueprint_zkevm_bbf_hardhat_test
    ./crypto3/libs/blueprint/test/blueprint_zkevm_bbf_hardhat_test -- --print
  '';

  cmakeBuildType = if enableDebug then "Debug" else "Release";
  doCheck = true;

  test_names = [
    "zkevm_bbf_hardhat_keccak_copy"
    "zkevm_bbf_hardhat_minimal_math_zkevm"
    "zkevm_bbf_hardhat_minimal_math_rw"
    "zkevm_bbf_hardhat_minimal_math_bytecode"

    "zkevm_bbf_hardhat_calldatacopy_copy"
    "zkevm_bbf_hardhat_exp_copy"
    "zkevm_bbf_hardhat_exp_rw"
    "zkevm_bbf_hardhat_minimal_math_copy"
    "zkevm_bbf_hardhat_modular_operations_copy"
  ];

  checkPhase = ''
    for test_name in ${lib.concatMapStringsSep " " lib.escapeShellArg test_names}; do
         set -x
         echo "Running ''${test_name}"
         ${proof-producer}/bin/proof-producer-multi-threaded -l trace \
            --stage "all" \
            --circuit "''${test_name}_circuit.crct" \
            --assignment-table="''${test_name}_table.tbl" -q 20
    done
  '';

  dontInstall = true;
  installPhase = "true";

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to verify-proofs environment!"
  '';
}
