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
      (test_name: "${binary} '--run_test=${test_suite}/${test_name}<*' -- --no-sat-check --proof --run-for-circuits=${lib.strings.concatStringsSep "," test_runs.${test_name}}\n")
      (builtins.attrNames test_runs)
  ;

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

  buildInputs = [cmake_modules];

  cmakeFlags =
  [
    (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" # to allow VSCode navigation/completion/etc
    "-DBUILD_TESTS=TRUE"
    "-G Ninja"
  ];

  buildPhase = ''
    ninja blueprint_zkevm_bbf_debugtt_test
  '';

  cmakeBuildType = if enableDebug then "Debug" else "Release";
  doCheck = true;

  test_lines = buildTestRunLines {
    binary = "./crypto3/libs/blueprint/test/zkevm_bbf/blueprint_zkevm_bbf_debugtt_test";

    test_suite = "zkevm_bbf_debugtt";

    test_runs = {

      # test case name
      keccak = [ # circuit names
        "copy"
        "keccak"
        "rw"
        "bytecode"
        "zkevm"
      ];

      minimal_math = [ "zkevm" "zkevm-wide" "copy" "keccak" "rw"  ];
      try_catch = [ "zkevm" "zkevm-wide" "copy" "bytecode" "rw" ];
      exp = [ "copy" "rw" "bytecode" "zkevm" "exp" ];

      # Need traces in new format
      # calldatacopy = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];
      # logger = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];
      # returndatacopy = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak" ];
      # mstore8 = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];
      # modular_operations = [ "copy" "rw" "bytecode" "zkevm" "exp" "keccak"];
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
