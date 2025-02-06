# stolen from nixpkgs (/pkgs/development/compilers/opensycl/default.nix
# we need a custom version because (at the time of writing) the nixpkgs version is broken
{ lib
, fetchFromGitHub
, llvmPackages_19
, lld_19
, python3
, cmake
, boost
, libxml2
, libffi
, makeWrapper
, config
, cudaPackages
, linuxPackages
, rocmPackages_5
, ompSupport ? true
, openclSupport ? false
, rocmSupport ? config.rocmSupport
, cudaSupport
, autoAddDriverRunpath
}:
let
  inherit (llvmPackages_19) stdenv;
  # move to newer ROCm version once supported
  rocmPackages = rocmPackages_5;
in
stdenv.mkDerivation rec {
  pname = "AdaptiveCpp";
  version = "24.10.0";

  src = fetchFromGitHub {
    owner = "AdaptiveCpp";
    repo = "AdaptiveCpp";
    rev = "v24.10.0";
    sha256 = "sha256-ZwHDiwv1ybC+2UhiOe2f7fnfqcul+CD9Uta8PT9ICr4=";
  };
  # zerocallusedregs is disabled because passing it to gpu compilers confuses them
  # fortify is disabled because it was also disabled above in flake, idk why
  hardeningDisable = [ "fortify" "zerocallusedregs" ];

  nativeBuildInputs = [
    cmake
    makeWrapper
  ] ++ lib.optionals cudaSupport [
    autoAddDriverRunpath
    linuxPackages.nvidia_x11
    cudaPackages.cuda_nvcc
    cudaPackages.cuda_cudart
    cudaPackages.cudatoolkit
    cudaPackages.cuda_nvrtc
    cudaPackages.cuda_cupti
  ];

  buildInputs = [
    libxml2
    libffi
    boost
    llvmPackages_19.openmp
    llvmPackages_19.llvm
    llvmPackages_19.libclang.dev
  ] ++ lib.optionals rocmSupport [
    rocmPackages.clr
    rocmPackages.rocm-runtime
  ] ++ lib.optionals cudaSupport [
    linuxPackages.nvidia_x11
    cudaPackages.cuda_cudart
    (lib.getOutput "stubs" cudaPackages.cuda_cudart)
  ];

  # set the gpu architecture for the cuda backend here
  NIX_CXXFLAGS_COMPILE = lib.optionalString cudaSupport "--cuda-gpu-arch=sm_89";
  # opensycl makes use of clangs internal headers. Its cmake does not successfully discover them automatically on nixos, so we supply the path manually
  cmakeFlags = [
    "-DCLANG_INCLUDE_PATH=${llvmPackages_19.libclang.dev}/include"
  ] ++ lib.optionals cudaSupport [
    "-DCMAKE_CUDA_COMPILER=$(which nvcc)"
  ] ++ [
    (lib.cmakeBool "WITH_CPU_BACKEND" ompSupport)
    (lib.cmakeBool "WITH_CUDA_BACKEND" cudaSupport)
    (lib.cmakeBool "WITH_ROCM_BACKEND" rocmSupport)
  ] ++ lib.optionals (lib.versionAtLeast version "24") [
    (lib.cmakeBool "WITH_OPENCL_BACKEND" openclSupport)
  ];

  postFixup = ''
    wrapProgram $out/bin/syclcc-clang \
      --prefix PATH : ${lib.makeBinPath [ python3 lld_19 ]} \
  '' + lib.optionalString rocmSupport ''
    --add-flags "--rocm-device-lib-path=${rocmPackages.rocm-device-libs}/amdgcn/bitcode"
  '';

  meta = with lib; {
    homepage = "https://github.com/AdaptiveCpp/AdaptiveCpp";
    description = "Multi-backend implementation of SYCL for CPUs and GPUs";
    maintainers = with maintainers; [ yboettcher ];
    license = licenses.bsd2;
  };
}