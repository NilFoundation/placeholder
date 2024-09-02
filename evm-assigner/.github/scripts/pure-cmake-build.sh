#!/bin/bash -e

nix develop -c "env" | grep CMAKE_PREFIX_PATH >cmake_prefix
echo "export `cat cmake_prefix`" > cmake_prefix
source cmake_prefix
cat cmake_prefix
rm cmake_prefix
CMAKE_BINARY=$(nix develop -c bash -c 'which cmake' | tail -1)
NINJA_BINARY=$(nix develop -c bash -c 'which ninja' | tail -1)
CC=$(nix develop -c bash -c 'which gcc' | tail -1)
CXX=$(nix develop -c bash -c 'which g++' | tail -1)
set -x
$CMAKE_BINARY -GNinja -DCMAKE_MAKE_PROGRAM=$NINJA_BINARY -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DBUILD_ASSIGNER_TESTS=TRUE
$NINJA_BINARY -C build
