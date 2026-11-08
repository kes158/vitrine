#!/bin/sh
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SRC="$ROOT/tweak/Sources"
APP="$ROOT/harness/wireguard/build/WGSettings.app"
mkdir -p "$APP"
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun clang -target arm64-apple-ios17.0-simulator -isysroot "$SDK" -fobjc-arc -I"$SRC" \
  -Wall -Werror -Wno-deprecated-declarations \
  "$ROOT/harness/wireguard/settings.m" "$ROOT/harness/scene.m" \
  "$SRC/Shared/WireGuard/SGWGSettingsController.m" "$SRC/Core/SGLocalize.m" \
  -framework UIKit -framework UniformTypeIdentifiers -framework Foundation -o "$APP/WGSettings"
cp -R "$ROOT/tweak/layout/Library/Application Support/Vitrine.bundle" "$APP/"
cat > "$APP/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>WGSettings</string>
<key>CFBundleIdentifier</key><string>com.vitrine.wgsettings</string>
<key>CFBundleName</key><string>WireGuard Settings</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>UILaunchScreen</key><dict/>
<key>UIUserInterfaceStyle</key><string>Dark</string>
<key>UIApplicationSceneManifest</key><dict>
<key>UISceneConfigurations</key><dict><key>UIWindowSceneSessionRoleApplication</key><array><dict>
<key>UISceneConfigurationName</key><string>Default</string>
<key>UISceneDelegateClassName</key><string>SGRHarnessScene</string>
</dict></array></dict></dict>
</dict></plist>
PLIST
echo "$APP"
