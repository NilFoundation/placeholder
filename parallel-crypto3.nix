{ lib,
  pkgs,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  boost,
  gdb,
  lldb,
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
  #opensycl,
  #cudatoolkit,
  enableDebugging,
  enableDebug ? false,
  runTests ? false,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "Parallel Crypto3";

  src = lib.sourceByRegex ./. ["^crypto3(/.*)?$" "^parallel-crypto3(/.*)?$" "CMakeLists.txt"];
  hardeningDisable = [ "fortify" ];
  # libgcc gcc glibc libffi libxml2 icu70 ncurses xz libedit llvm libcxx libstdcxx5 libz
  nativeBuildInputs = [ cmake ninja pkg-config llvmPackages_19.openmp ] ++
                       (lib.optional (!stdenv.isDarwin) gdb) ++
                       (lib.optional (stdenv.isDarwin) lldb);

  # enableDebugging will keep debug symbols in boost
  propagatedBuildInputs = [ (if enableDebug then (enableDebugging boost) else boost) ];

  buildInputs = [cmake_modules];

  cmakeFlags =
    [
      (if runTests then "-DBUILD_PARALLEL_CRYPTO3_TESTS=TRUE" else "")
      (if enableDebug then "-DCMAKE_BUILD_TYPE=Debug" else "-DCMAKE_BUILD_TYPE=Release")
      "-DPARALLEL_CRYPTO3_ENABLE=TRUE"
      #"-DCMAKE_CUDA_HOST_COMPILER=/nix/store/ykv9x1iirnkxfdnyzwhfzhz23csqvqn9-clang-wrapper-19.1.1/bin/clang++"
      #"-DCMAKE_CXX_COMPILER_WORKS=1"
    ];

  doCheck = runTests; # tests are inside parallel-crypto3-tests derivation
  dontFixCmake = true;
  checkPhase = ''
    cd parallel-crypto3 && ctest --verbose --output-on-failure -R && cd ..
  '';

  shellHook = ''
    NVARCH=`uname -s`_`uname -m`; export NVARCH
    NVCOMPILERS=/opt/nvidia/hpc_sdk; export NVCOMPILERS
    MANPATH=$MANPATH:$NVCOMPILERS/$NVARCH/24.9/compilers/man; export MANPATH
    PATH=/root/acpp/bin/:$NVCOMPILERS/$NVARCH/24.9/compilers/bin:$PATH; export PATH
    CXX=/root/acpp/bin/acpp; export CXX
    # source /opt/intel/oneapi/setvars.sh
    # PATH=/root/sycl_workspace/llvm/build/install/bin/:$PATH; export PATH
    # DCPP_HOME=/root/sycl_workspace/; export DCPP_HOME
    # LD_LIBRARY_PATH=/root/sycl_workspace/llvm/build/lib/; export LD_LIBRARY_PATH
    rm -rf build
    eval $configurePhase
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to Parallel Crypto3 development environment!"
  '';
}
