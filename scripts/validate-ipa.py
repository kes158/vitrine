#!/usr/bin/env python3
"""Validate a downloaded Spotify IPA by its contents, not libmagic's MIME label."""
import argparse
import plistlib
import re
import sys
import zipfile
from pathlib import Path
from xml.parsers.expat import ExpatError


class InvalidIPA(ValueError):
    pass


def spotify_version(path):
    if not zipfile.is_zipfile(path):
        raise InvalidIPA(
            "Download is not an IPA/ZIP. Use a direct file download URL, not a "
            "share/preview page or a link requiring login. The response may also "
            "be an expired-link or download-limit page."
        )
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        plists = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        if len(plists) != 1:
            raise InvalidIPA("IPA must contain exactly one Payload/*.app/Info.plist.")
        info = plistlib.loads(archive.read(plists[0]))
        if not isinstance(info, dict) or info.get("CFBundleIdentifier") != "com.spotify.client":
            raise InvalidIPA("IPA is not the original Spotify app (com.spotify.client).")
        executable = info.get("CFBundleExecutable")
        if executable != "Spotify" or plists[0].removesuffix("Info.plist") + executable not in names:
            raise InvalidIPA("IPA is missing the Spotify executable.")
        version = info.get("CFBundleShortVersionString")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version):
            raise InvalidIPA("IPA has no valid Spotify version.")
        # Stream members to check CRCs before expensive toolchain installation/builds.
        if archive.testzip() is not None:
            raise InvalidIPA("IPA is corrupt; download the original file again.")
        return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        version = spotify_version(args.ipa)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, ExpatError, NotImplementedError) as error:
        # Never print response bodies, member names, URLs or parser errors: links
        # can be private and the download is untrusted workflow input.
        message = str(error) if isinstance(error, InvalidIPA) else "IPA could not be read or is corrupt."
        print(f"::error::{message}", file=sys.stderr)
        return 1
    if args.github_output:
        with args.github_output.open("a") as output:
            output.write(f"version={version}\n")
    print(f"Validated Spotify {version} IPA archive (this does not verify decryption).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
