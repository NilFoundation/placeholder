{ lib,
  stdenv,
  ninja,
  pkg-config,
  cmake,
  crypto3,
  boost,
  gdb,
  cmake_modules,
  }:
let
  inherit (lib) optional;
in stdenv.mkDerivation {
  name = "debug-tools";

  src = lib.sourceByRegex ./. [ ".*" ];

  nativeBuildInputs = [ cmake ninja pkg-config ] ++ (lib.optional (!stdenv.isDarwin) gdb);

  buildInputs = [ cmake_modules crypto3 ];

  cmakeFlags =
    [
      "-DCMAKE_BUILD_TYPE=Release"
      "-G Ninja"
    ];

  shellHook = ''
    PS1="\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
    echo "Welcome to debug-tools development environment!"
  '';
}
