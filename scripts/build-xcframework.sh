#!/bin/sh
# Builds the C API for iOS devices and the iOS simulator and folds the two
# into one uconnect_c.xcframework, the form an Xcode project links and embeds.
# Needs a Mac with Xcode, CMake 3.28+ and Ninja.
#
#   sh scripts/build-xcframework.sh [output directory]     (default: build-ios)
#
# IOS_DEPLOYMENT_TARGET sets the lowest iOS version (default 15.0, the lowest
# the C++ standard library of current Xcode versions supports).
#
# uconnect_c is a dynamic framework: an application embeds it (Embed & Sign)
# and opens uconnect_c.framework/uconnect_c, by name from an FFI or by linking
# it. Nothing else of the library needs shipping.
set -e
root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:-$root/build-ios}"
target="${IOS_DEPLOYMENT_TARGET:-15.0}"

build() { # <dir> <sysroot> <archs>
  cmake -S "$root" -B "$out/$1" -G Ninja \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_SYSROOT="$2" \
    -DCMAKE_OSX_ARCHITECTURES="$3" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$target" \
    -DCMAKE_BUILD_TYPE=Release \
    -DUCONNECT_BUILD_TESTS=OFF -DUCONNECT_BUILD_SERVER=OFF
  cmake --build "$out/$1" --target uconnect_c
}

build device iphoneos arm64
build simulator iphonesimulator "arm64;x86_64"

rm -rf "$out/uconnect_c.xcframework"
xcodebuild -create-xcframework \
  -framework "$out/device/src/capi/uconnect_c.framework" \
  -framework "$out/simulator/src/capi/uconnect_c.framework" \
  -output "$out/uconnect_c.xcframework"
echo "made $out/uconnect_c.xcframework"
