import importlib.util
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate-ipa.py")
spec = importlib.util.spec_from_file_location("validate_ipa", SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class DownloadValidation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "spotify.ipa"

    def write_ipa(self, *, binary=True, bundle="com.spotify.client", version="9.1.90"):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("Payload/Spotify.app/Info.plist", plistlib.dumps({
                "CFBundleIdentifier": bundle, "CFBundleExecutable": "Spotify",
                "CFBundleShortVersionString": version,
            }, fmt=plistlib.FMT_BINARY))
            if binary:
                archive.writestr("Payload/Spotify.app/Spotify", b"synthetic executable fixture")

    def test_valid_archive_and_workflow_version_output(self):
        self.write_ipa()
        output = self.path.with_suffix(".output")
        run = subprocess.run([sys.executable, "-B", str(SCRIPT), str(self.path),
                              "--github-output", str(output)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(output.read_text(), "version=9.1.90\n")

    def test_html_download_reports_direct_link_requirement_without_echoing_body(self):
        self.path.write_text("<html>private download token</html>")
        run = subprocess.run([sys.executable, "-B", str(SCRIPT), str(self.path)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertIn("direct file download URL", run.stderr)
        self.assertNotIn("private download token", run.stdout + run.stderr)

    def test_zip_without_app_is_rejected(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("readme.txt", "not an IPA")
        with self.assertRaisesRegex(ValueError, "Info.plist"):
            validator.spotify_version(self.path)

    def test_non_spotify_app_is_rejected(self):
        self.write_ipa(bundle="example.other")
        with self.assertRaisesRegex(ValueError, "original Spotify"):
            validator.spotify_version(self.path)

    def test_missing_binary_is_rejected(self):
        self.write_ipa(binary=False)
        with self.assertRaisesRegex(ValueError, "executable"):
            validator.spotify_version(self.path)

    def test_version_cannot_inject_workflow_outputs(self):
        self.write_ipa(version="9.1.90\ninjected=value")
        with self.assertRaisesRegex(ValueError, "version"):
            validator.spotify_version(self.path)

    def test_corrupt_member_is_rejected(self):
        self.write_ipa()
        data = self.path.read_bytes().replace(b"synthetic executable fixture", b"Synthetic executable fixture")
        self.path.write_bytes(data)
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            validator.spotify_version(self.path)

    def test_malformed_plist_fails_cleanly_without_writing_outputs(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("Payload/Spotify.app/Info.plist", b"<?xml version='1.0'?><private")
        output = self.path.with_suffix(".output")
        run = subprocess.run([sys.executable, "-B", str(SCRIPT), str(self.path),
                              "--github-output", str(output)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertIn("::error::", run.stderr)
        self.assertNotIn("Traceback", run.stderr)
        self.assertNotIn("private", run.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
