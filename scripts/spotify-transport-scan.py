#!/usr/bin/env python3
"""Read-only Spotify IPA transport preflight. Does not execute or patch the app."""
import argparse
import hashlib
import json
import plistlib
import re
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

INSPECTED_UUIDS = {
    "9.1.90": {
        "Spotify": "fbce22c17e1b3e0d9be866ff9291943e",
        "Frameworks/SpotifyShared.framework/SpotifyShared": "2e074234cfc63f0e9255c9881824167a",
    },
    "9.1.94": {
        "Spotify": "1dfddfa139c03735b9a5fdfa475f4700",
        "Frameworks/SpotifyShared.framework/SpotifyShared": "2c12ca8c48ad33f8af6569c084a6324f",
    },
}
REQUIRED = {
    "Spotify": ["SPTCoreURLSessionDataDelegate", "_TtC26Connectivity_HttpClientKit20HttpClientURLSession"],
    "Frameworks/SpotifyShared.framework/SpotifyShared": ["SPTDataLoaderService"],
}
SELECTORS = ["URLSession:task:didCompleteWithError:", "URLSession:dataTask:didReceiveData:"]
NATIVE_IMPORTS = ["nw_connection_create", "connect", "getaddrinfo", "sendto", "sendmsg"]


def macho(data):
    if len(data) < 32 or struct.unpack_from("<I", data)[0] != 0xFEEDFACF:
        raise ValueError("Expected thin arm64 Mach-O")
    if struct.unpack_from("<I", data, 4)[0] != 0x100000C:
        raise ValueError("Expected arm64")
    offset, uuid, encryption = 32, None, []
    for _ in range(struct.unpack_from("<I", data, 16)[0]):
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > len(data):
            raise ValueError("Invalid load command")
        if command == 0x1B:
            uuid = data[offset + 8:offset + 24].hex()
        if command == 0x2C:
            encryption.append(struct.unpack_from("<I", data, offset + 16)[0])
        offset += size
    if any(encryption):
        raise ValueError("Executable is still encrypted")
    return {"uuid": uuid, "cryptid": encryption}


def wireguard_version(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not match:
        raise ValueError(f"Unrecognized Spotify version: {version}")
    parts = tuple(map(int, match.groups()))
    if parts != (9, 1, 90) and parts < (9, 1, 94):
        raise ValueError("WireGuard requires Spotify 9.1.90 or 9.1.94 and newer")
    return "inspected IPA" if version in INSPECTED_UUIDS else "future version: static transport check only"


def scan(path, require_version=None, wireguard_compatible=False):
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory(prefix="spotify-transport-") as temp:
        info = plistlib.loads(archive.read("Payload/Spotify.app/Info.plist"))
        if info.get("CFBundleIdentifier") != "com.spotify.client":
            raise ValueError("Expected original Spotify bundle identifier")
        version = info.get("CFBundleShortVersionString")
        if require_version and version != require_version:
            raise ValueError(f"Expected Spotify {require_version}; got {version}")
        result = {"version": version, "build": info.get("CFBundleVersion"), "images": {}}
        if wireguard_compatible:
            result["wireguard_compatibility"] = wireguard_version(version)
        for name, classes in REQUIRED.items():
            data = archive.read("Payload/Spotify.app/" + name)
            record = macho(data)
            expected = INSPECTED_UUIDS.get(version, {}).get(name)
            if (wireguard_compatible or require_version) and expected and record["uuid"] != expected:
                raise ValueError(f"Spotify {version} {name} differs from the inspected IPA; re-verify it first")
            if (wireguard_compatible and not record["uuid"]):
                raise ValueError(f"Spotify {version} {name} has no Mach-O UUID")
            binary = Path(temp) / Path(name).name
            binary.write_bytes(data)
            output = subprocess.run(["xcrun", "dyld_info", "-objc", str(binary)], check=True, capture_output=True, text=True).stdout
            record["classes"] = {}
            for cls in classes:
                block = re.search(r"@interface " + re.escape(cls) + r"\s.*?@end", output, re.S)
                methods = {sel: bool(block and f" {sel}]" in block[0]) for sel in SELECTORS}
                if not all(methods.values()):
                    raise ValueError(f"Required transport selectors missing: {cls}")
                record["classes"][cls] = methods
            if name == "Spotify":
                imported = subprocess.run(["xcrun", "dyld_info", "-imports", str(binary)],
                                          check=True, capture_output=True, text=True).stdout
                record["native_imports"] = {
                    symbol: bool(re.search(r"\s_" + re.escape(symbol) + r"\s+\(from ", imported))
                    for symbol in NATIVE_IMPORTS
                }
                if (wireguard_compatible or require_version) and not all(record["native_imports"].values()):
                    raise ValueError(f"Required native transport import missing from Spotify {version}")
            result["images"][name] = record
        result["evidence"] = "Static class/selector/import presence only; runtime ABI, all Vitrine features and device playback must also be checked."
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--require-version")
    parser.add_argument("--wireguard-compatible", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        result = scan(args.ipa, args.require_version, args.wireguard_compatible)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Spotify transport preflight failed: {error}\n")
    text = json.dumps(result, indent=2) + "\n"
    print(text, end="")
    if args.out:
        args.out.write_text(text)
