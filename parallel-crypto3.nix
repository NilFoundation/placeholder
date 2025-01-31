{ lib,
  pkgs,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
  lldb,
  mold,
  cmake_modules,
  libgcc,
  glibc,
  libffi,
  libz,
  libxml2,
  icu70,
  ncurses,
  gcc,
  xz,
  libedit,
  llvm,
  libcxx,
  libstdcxx5,
  llvmPackages_19,
  opensycl,
  enableDebugging,
  enableGPU ? false,
  enableDebug ? false,
  runTests ? false,
  sanitize? false,
  benchmarkTests ? false,
  }:
let
  inherit (lib) optional;
  opensycl = pkgs.callPackage ./opensycl.nix {
    inherit (pkgs);
    cudaSupport = enableGPU;
  };

in stdenv.mkDerivation {
  name = "Parallel Crypto3";

  src = lib.sourceByRegex ./. ["^crypto3(/.*)?$" "^parallel-crypto3(/.*)?$" "CMakeLists.txt"];
  hardeningDisable = [ "fortify" "zerocallusedregs" ];
  nativeBuildInputs = [ cmake ninja pkg-config llvmPackages_19.openmp opensycl  ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [
    cmake_modules
    opensycl
  ] ++ (if enableGPU then [
    pkgs.cudaPackages.cudatoolkit
    pkgs.cudaPackages.cuda_cudart
    pkgs.cudaPackages.cuda_nvcc
    pkgs.linuxPackages.nvidia_x11
  ] else []);

  makeWrapperArgs = [
  # Ensure the real NVIDIA libraries are found first
    "--prefix LD_LIBRARY_PATH : ${pkgs.linuxPackages.nvidia_x11}/lib"
  ];

  cmakeFlags =
    [
      (if runTests then "-DBUILD_PARALLEL_CRYPTO3_TESTS=TRUE" else "")
      (if sanitize then "-DSANITIZE=ON" else "-DSANITIZE=OFF")
      (if benchmarkTests then "-DENABLE_BENCHMARKS=ON" else "-DENABLE_BENCHMARKS=OFF")
      (if enableGPU then "-DGPU_PROVER=ON" else "")
      "-DPARALLEL_CRYPTO3_ENABLE=TRUE"
    ];

  cmakeBuildType = if enableDebug then "Debug" else "Release";
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

  shellHook =
  (if enableGPU then ''
    CXX=syclcc-clang; export CXX
    ACPP_ADAPTIVITY_LEVEL=2; export ACPP_ADAPTIVITY_LEVEL
  '' else "") +
  ''
    rm -rf build
    eval $configurePhase
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Parallel Crypto3 development environment!"
  '';
}
