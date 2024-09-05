#!/usr/bin/env bash

set -eu

# Directories to search for source files
DIRS=(bin libs tests)

# Extensions to match
EXTENSIONS=(.cpp .hpp .c .h)

CLANG_FORMAT_FLAGS="--dry-run --Werror"
while test $# -gt 0; do
  case "$1" in
  -i|--inplace)
    CLANG_FORMAT_FLAGS="-i"
    break
    ;;
  -h|--help)
    MY_NAME=$(basename "$0")
    echo "${MY_NAME} [-i|--inplace]"
    echo ""
    echo "  -i|--inplace - apply changes inplace"
    exit 0
    break
  esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ROOT_DIR=$(realpath ${SCRIPT_DIR}/..)

CLANG_FORMAT_CFG=${ROOT_DIR}/.clang-format

DIRS_ABS=()
for DIR in "${DIRS[@]}"; do
  DIRS_ABS+=(${ROOT_DIR}/${DIR})
done

NAME_ARGS=()
for EXT in "${EXTENSIONS[@]}"; do
  NAME_ARGS+=("-iname *${EXT}")
done

# https://stackoverflow.com/a/17841619
function join_by {
  local d=${1-} f=${2-}
  if shift 2; then
    printf %s "$f" "${@/#/$d}"
  fi
}
FIND_ARGS=$(join_by ' -or ' "${NAME_ARGS[@]}")

CMD="find ${DIRS_ABS[@]} ${FIND_ARGS} | xargs clang-format -style=file:${CLANG_FORMAT_CFG} ${CLANG_FORMAT_FLAGS}"

echo "${CMD}"
eval "${CMD}"
