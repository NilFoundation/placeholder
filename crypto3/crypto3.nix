{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
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

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

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

  preBuild = ''
    echo "build RAM-consuming tests with 4 cores only"
    ninja -j4 -k 0
      crypto3_zk_systems_plonk_placeholder_placeholder_curves_test \
      marshalling_zk_placeholder_proof_test \
      pubkey_ecdsa_test \
      crypto3_zk_commitment_kzg_test \
      blueprint_algebra_fields_plonk_non_native_lookup_logic_ops_test \
      blueprint_algebra_fields_plonk_non_native_logic_ops_test \
      pubkey_bls_test \
      crypto3_zk_commitment_lpc_test \
      crypto3_containers_merkle_test \
      crypto3_zk_commitment_fold_polynomial_test \
      hash_hash_to_curve_test \
      pubkey_eddsa_test \
      crypto3_zk_commitment_proof_of_work_test \
      crypto3_zk_commitment_proof_of_knowledge_test || echo "Skip building tests. Ignore error if runTests=false"
    echo "end building with 4 cores"
  '';

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
