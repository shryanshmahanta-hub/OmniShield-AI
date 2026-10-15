#!/usr/bin/env python3
"""Fetch openly published security datasets into datasets/raw (not bundled by default).

Use only after reviewing the source dataset's license, privacy risks and suitability.
EMBER downloads are large; require explicit --ember2018 opt-in and SHA-256 verification.
"""
from __future__ import annotations
import argparse
import hashlib
import shutil
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "datasets" / "raw"
SOURCES = {
    "sms": ("https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip", "sms_spam_collection.zip"),
    "email": ("https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv", "phishing_email.csv"),
}
EMBER_URL = "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
EMBER_SHA256 = "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"


def fetch(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    print(f"Downloading {url}\n  -> {dest}")
    request = urllib.request.Request(url, headers={"User-Agent": "OmniShield-AI-dataset-fetcher/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response, tmp.open("wb") as out:
        shutil.copyfileobj(response, out)
    tmp.replace(dest)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sms", action="store_true", help="Download UCI SMS Spam Collection ZIP")
    parser.add_argument("--email", action="store_true", help="Download Hugging Face phishing email CSV (52 MB, LGPL-3.0 listed)")
    parser.add_argument("--ember2018", action="store_true", help="Download large EMBER 2018 feature archive and verify SHA-256")
    parser.add_argument("--all-small", action="store_true", help="Download SMS and email sources")
    args = parser.parse_args()
    if not (args.sms or args.email or args.ember2018 or args.all_small):
        parser.print_help()
        return 0
    ROOT.mkdir(parents=True, exist_ok=True)
    if args.sms or args.all_small:
        url, name = SOURCES["sms"]
        path = ROOT / "sms_spam" / name
        fetch(url, path)
        with zipfile.ZipFile(path) as archive:
            # Extract only corpus and README into a dedicated source directory.
            target = ROOT / "sms_spam"
            for member in archive.namelist():
                base_name = Path(member).name
                if base_name in {"SMSSpamCollection", "readme"} or base_name.lower() == "readme":
                    # Write only selected basenames. Never trust archive paths for extraction.
                    dest = target / base_name
                    with archive.open(member) as src, dest.open("wb") as out:
                        shutil.copyfileobj(src, out)
        print("UCI SMS collection downloaded. Attribute it to UCI and follow CC BY 4.0 terms.")
    if args.email or args.all_small:
        url, name = SOURCES["email"]
        path = ROOT / "phishing_email" / name
        fetch(url, path)
        print("Email CSV downloaded. Verify the dataset card/redistribution rights and inspect labels before training.")
    if args.ember2018:
        path = ROOT / "ember" / "ember_dataset_2018_2.tar.bz2"
        if not path.exists():
            print("WARNING: EMBER archive is large. It contains extracted PE feature records, not executable malware samples.")
            fetch(EMBER_URL, path)
        actual = sha256(path)
        if actual != EMBER_SHA256:
            path.unlink(missing_ok=True)
            raise SystemExit(f"SHA-256 mismatch; deleted archive. Expected {EMBER_SHA256}, got {actual}")
        print(f"EMBER archive SHA-256 verified: {actual}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
