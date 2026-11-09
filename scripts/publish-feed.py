"""Only promote a published release with a valid Sparkle archive signature."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

REPO = "yednapg/broccoli-releases"
NS = "http://www.andymatuschak.org/xml-namespaces/sparkle"


def gh(*args, check=True):
    return subprocess.run(["gh", *args, "--repo", REPO], check=check, capture_output=True, text=True)


def verify_candidate(xml, tag, archive, public_key):
    match = re.fullmatch(r"(public|beta|dev)-v([0-9]+(?:\.[0-9]+){0,2})-build([1-9][0-9]*)", tag)
    if not match:
        raise ValueError("Only numbered app releases can update a feed")
    channel, version, build = match.groups()
    root = ET.fromstring(xml)
    items = root.findall("channel/item")
    if len(items) != 1:
        raise ValueError("Expected one channel item")
    item = items[0]
    if item.findtext(f"{{{NS}}}version") != build or item.findtext(f"{{{NS}}}shortVersionString") != version:
        raise ValueError("Feed version does not match release")
    enclosure = item.find("enclosure")
    expected = f"https://github.com/{REPO}/releases/download/{tag}/{tag}.zip"
    if enclosure is None or enclosure.get("url") != expected or int(enclosure.get("length", "0")) != archive.stat().st_size:
        raise ValueError("Feed does not refer to this release archive")
    key = base64.b64decode(public_key.strip(), validate=True)
    signature = base64.b64decode(enclosure.get(f"{{{NS}}}edSignature", ""), validate=True)
    if len(key) != 32 or len(signature) != 64:
        raise ValueError("Invalid update key or signature")
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        # RFC 8410 SubjectPublicKeyInfo prefix for a raw Ed25519 public key.
        (directory / "key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + key)
        (directory / "signature").write_bytes(signature)
        subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                        "-inkey", str(directory / "key.der"), "-rawin", "-in", str(archive),
                        "-sigfile", str(directory / "signature")], check=True)
    return channel, int(build)


def main():
    tag = os.environ["RELEASE_TAG"]
    if not re.fullmatch(r"(public|beta|dev)-v[0-9]+(?:\.[0-9]+){0,2}-build[1-9][0-9]*", tag):
        raise ValueError("Invalid release tag")
    release = json.loads(gh("release", "view", tag, "--json", "isDraft,isPrerelease").stdout)
    if release["isDraft"] or release["isPrerelease"] != (not tag.startswith("public-")):
        raise ValueError("Release visibility/channel mismatch")
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        for name in ("candidate-appcast.xml", "SHA256SUMS", f"{tag}.zip"):
            gh("release", "download", tag, "--pattern", name, "--dir", str(directory))
        archive = directory / f"{tag}.zip"
        expected = f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}"
        if (directory / "SHA256SUMS").read_text().strip() != expected:
            raise ValueError("Archive checksum mismatch")
        xml = (directory / "candidate-appcast.xml").read_bytes()
        channel, build = verify_candidate(xml, tag, archive, Path("SparklePublicKey.txt").read_text())
        feed_tag = f"updates-{channel}"
        existing = gh("release", "view", feed_tag, "--json", "assets", check=False)
        if existing.returncode == 0 and any(a["name"] == "appcast.xml" for a in json.loads(existing.stdout)["assets"]):
            gh("release", "download", feed_tag, "--pattern", "appcast.xml", "--dir", str(directory))
            old = ET.fromstring((directory / "appcast.xml").read_bytes())
            old_build = int(old.findtext(f"channel/item/{{{NS}}}version", "0"))
            if old_build >= build:
                print("An equal or newer build is already published; retaining that feed.")
                return
        if existing.returncode != 0:
            gh("release", "create", feed_tag, "--title", f"{channel} update feed", "--notes",
               "Machine-readable update feed. Download numbered app releases instead.", "--prerelease", "--latest=false")
        (directory / "appcast.xml").write_bytes(xml)
        gh("release", "upload", feed_tag, str(directory / "appcast.xml"), "--clobber")
        print(f"Published {channel} update feed for build {build}.")


if __name__ == "__main__":
    main()
