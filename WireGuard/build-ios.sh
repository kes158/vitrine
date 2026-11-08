#!/usr/bin/env bash
# Builds the app-local WireGuard engine (wireguard-go + gVisor netstack) as a
# static c-archive for iOS arm64: WireGuard/build/libsgwg.a
#
# macOS: uses Xcode's iPhoneOS SDK via xcrun.
# Linux: set IOS_SDK=/path/to/iPhoneOS.sdk (clang must support -target arm64-apple-ios).
# Requires Go matching WireGuard/go.mod (GOTOOLCHAIN downloads it if needed).
set -euo pipefail
cd "$(dirname "$0")"

MIN_IOS="${MIN_IOS:-16.0}"  # same deployment target as the tweak (Makefile TARGET)
if [[ -z "${IOS_SDK:-}" ]]; then
  IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
  CLANG="$(xcrun --sdk iphoneos --find clang)"
else
  CLANG="${CLANG:-clang}"
fi
FLAGS="-target arm64-apple-ios${MIN_IOS} -isysroot ${IOS_SDK} -miphoneos-version-min=${MIN_IOS}"

mkdir -p build
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
  CC="${CLANG} ${FLAGS}" CGO_CFLAGS="${FLAGS} -O2" CGO_LDFLAGS="${FLAGS}" \
  go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -buildmode=c-archive \
  -o build/libsgwg.a .

# GNU ar (Linux) cannot index Mach-O members; Apple's ld64 and lld need an index.
if [[ "$(uname)" == "Darwin" ]]; then
  xcrun ranlib build/libsgwg.a
elif command -v llvm-ranlib >/dev/null; then
  llvm-ranlib build/libsgwg.a
fi

# Fail early if an export the Objective-C side relies on is missing.
for sym in SGWGInspect SGWGStart SGWGStatus SGWGRebind SGWGLookup SGWGRedact SGWGFree; do
  grep -q "${sym}" build/libsgwg.h || { echo "missing export ${sym}" >&2; exit 1; }
done
if command -v shasum >/dev/null; then shasum -a 256 build/libsgwg.a; else sha256sum build/libsgwg.a; fi
