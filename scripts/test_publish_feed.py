import base64
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-feed.py'))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.archive = self.path / 'dev-v0.0.1-build12.zip'
        self.archive.write_bytes(b'archive bytes used to exercise signature verification')
        key = self.path / 'key.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True)
        public = subprocess.check_output(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'])
        self.public_key = base64.b64encode(public[-32:]).decode()
        signature = subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-inkey', str(key), '-rawin', '-in', str(self.archive)])
        self.xml = f'''<rss xmlns:sparkle="{publisher.NS}"><channel><item>
        <sparkle:version>12</sparkle:version><sparkle:shortVersionString>0.0.1</sparkle:shortVersionString>
        <enclosure url="https://github.com/yednapg/broccoli-releases/releases/download/dev-v0.0.1-build12/dev-v0.0.1-build12.zip"
        length="{self.archive.stat().st_size}" sparkle:edSignature="{base64.b64encode(signature).decode()}" />
        </item></channel></rss>'''.encode()

    def test_suffix_release_identity_and_legacy_recovery(self):
        for suffix, channel in [("-dev", "dev"), ("-beta", "beta"), ("", "public")]:
            tag = f"v0.1.0{suffix}-build13"
            self.assertEqual(publisher.release_identity(tag), (channel, f"0.1.0{suffix}", "13"))
        self.assertEqual(publisher.release_identity("dev-v0.0.1-build12"), ("dev", "0.0.1", "12"))
        for tag in ["v0.1.0-ai-build13", "v0.1.0-beta-build0", "v0.1.0-build13;id"]:
            with self.assertRaises(ValueError):
                publisher.release_identity(tag)

    def test_suffix_archive_is_accepted(self):
        for suffix, channel in [("-dev", "dev"), ("-beta", "beta"), ("", "public")]:
            tag = f"v0.1.0{suffix}-build12"
            xml = self.xml.replace(b"dev-v0.0.1-build12", tag.encode()).replace(b">0.0.1<", f">0.1.0{suffix}<".encode())
            self.assertEqual(publisher.verify_candidate(xml, tag, self.archive, self.public_key), (channel, 12))

    def test_clean_tags_require_matching_internal_build_metadata(self):
        for suffix, channel in [("-dev", "dev"), ("-beta", "beta"), ("", "public")]:
            tag = f"v0.1.0{suffix}"
            self.assertEqual(publisher.release_identity(tag), (channel, f"0.1.0{suffix}", None))
            xml = self.xml.replace(b"dev-v0.0.1-build12", tag.encode()).replace(b">0.0.1<", f">0.1.0{suffix}<".encode())
            self.assertEqual(publisher.verify_candidate(xml, tag, self.archive, self.public_key, "12"), (channel, 12))
            for expected in (None, "13", "0", "garbage"):
                with self.assertRaises(ValueError):
                    publisher.verify_candidate(xml, tag, self.archive, self.public_key, expected)

    def test_valid_archive_is_accepted(self):
        self.assertEqual(publisher.verify_candidate(self.xml, 'dev-v0.0.1-build12', self.archive, self.public_key), ('dev', 12))

    def test_other_channel_cannot_use_archive(self):
        with self.assertRaises(ValueError):
            publisher.verify_candidate(self.xml, 'beta-v0.0.1-build12', self.archive, self.public_key)

    def test_modified_archive_fails_signature(self):
        original = self.archive.read_bytes()
        self.archive.write_bytes(b'X' + original[1:])
        with self.assertRaises(subprocess.CalledProcessError):
            publisher.verify_candidate(self.xml, 'dev-v0.0.1-build12', self.archive, self.public_key)

    def test_mismatched_version_is_rejected(self):
        with self.assertRaises(ValueError):
            publisher.verify_candidate(self.xml.replace(b'>12<', b'>13<'), 'dev-v0.0.1-build12', self.archive, self.public_key)


if __name__ == '__main__':
    unittest.main()
