#!/usr/bin/env bash
# Builds the app-local WireGuard engine (wireguard-go + gVisor netstack, Go) as a static c-archive for
# iOS arm64: vendor/wireguard/build/ios/libsgwg.a and its header. tweak/Makefile runs it for WIREGUARD=1
# builds; an archive newer than every Go source is kept.
#
# macOS: uses Xcode's iPhoneOS SDK via xcrun.
# Linux: set IOS_SDK=/path/to/iPhoneOS.sdk (clang must support -target arm64-apple-ios).
# Requires Go matching go.mod (GOTOOLCHAIN downloads it if needed).
set -euo pipefail
cd "$(dirname "$0")"

OUT=build/ios
LIB="$OUT/libsgwg.a"
if [[ -f "$LIB" && -f "$OUT/libsgwg.h" && -z "$(find . -name '*.go' -newer "$LIB" -o -name 'go.*' -newer "$LIB" | head -1)" ]]; then
  exit 0
fi

MIN_IOS="${MIN_IOS:-16.0}"  # the tweak's deployment target (tweak/Makefile TARGET)
if [[ -z "${IOS_SDK:-}" ]]; then
  IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
  CLANG="$(xcrun --sdk iphoneos --find clang)"
else
  CLANG="${CLANG:-clang}"
fi
FLAGS="-target arm64-apple-ios${MIN_IOS} -isysroot ${IOS_SDK} -miphoneos-version-min=${MIN_IOS}"

mkdir -p "$OUT"
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
go mod verify >/dev/null
GOOS=ios GOARCH=arm64 CGO_ENABLED=1 \
  CC="${CLANG} ${FLAGS}" CGO_CFLAGS="${FLAGS} -O2" CGO_LDFLAGS="${FLAGS}" \
  go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -buildmode=c-archive \
  -o "$LIB" .

# GNU ar (Linux) cannot index Mach-O members; Apple's ld64 and lld need an index.
if [[ "$(uname)" == "Darwin" ]]; then
  xcrun ranlib "$LIB"
elif command -v llvm-ranlib >/dev/null; then
  llvm-ranlib "$LIB"
fi

# Fail early if an export the Objective-C side relies on is missing (Shared/WireGuard/SGWGBridge.h).
for sym in SGWGInspect SGWGOpen SGWGAttachWireGuard SGWGAttachExternal SGWGFail SGWGForward SGWGExpectPeer \
           SGWGStatus SGWGRebind SGWGLookup SGWGRedact SGWGFree; do
  grep -q "${sym}" "$OUT/libsgwg.h" || { echo "missing export ${sym}" >&2; exit 1; }
done
# Test code must not end up in the tweak.
if strings "$LIB" | grep -q "sgwg/internal/testpeer"; then echo "test peer linked into the engine" >&2; exit 1; fi
if command -v shasum >/dev/null; then shasum -a 256 "$LIB"; else sha256sum "$LIB"; fi
