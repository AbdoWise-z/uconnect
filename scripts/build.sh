#!/usr/bin/env bash
# Configure + build + test. Usage: scripts/build.sh [ctest-args...]
set -e
cd "$(dirname "$0")/.."
source scripts/env.sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DUCONNECT_BUILD_TESTS=ON >/dev/null
cmake --build build
ctest --test-dir build --output-on-failure "$@"
