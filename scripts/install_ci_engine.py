#!/usr/bin/env python3
"""Install the pinned Linux CI engine from a checksum-verified reusable archive."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


VERSION = "1.13.19"
SHA256 = "ef88a9e577d474210867bd708933d042e9b70106529df2656182c9db90106aa1"
ASSET = f"sing-box-{VERSION}-linux-amd64"
URL = f"https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/{ASSET}.tar.gz"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024


def valid_archive(path: Path) -> bool:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ARCHIVE_BYTES:
        return False
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest() == SHA256


def download(destination: Path) -> None:
    # Releases occasionally return a burst of 504s. Space retries over minutes,
    # rather than the old four requests in seven seconds; all work stays bounded.
    subprocess.run(
        ["curl", "--proto", "=https", "--tlsv1.2", "--fail", "--silent", "--show-error",
         "--location", "--retry", "4", "--retry-all-errors", "--retry-delay", "15",
         "--retry-max-time", "180", "--connect-timeout", "15", "--max-time", "45",
         "--max-filesize", str(MAX_ARCHIVE_BYTES), URL, "--output", str(destination)],
        check=True, timeout=240,
    )


def install(cache: Path, bin_directory: Path) -> Path:
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not valid_archive(cache):
        # Never trust the Actions cache itself. A partial/corrupt entry is
        # repaired without touching the last installed executable.
        with tempfile.TemporaryDirectory(prefix="best50-engine-download-", dir=cache.parent) as temporary:
            candidate = Path(temporary) / "archive.tgz"
            download(candidate)
            if not valid_archive(candidate):
                raise RuntimeError("Pinned sing-box archive checksum/size validation failed")
            os.replace(candidate, cache)
        print("Downloaded and verified pinned sing-box archive")
    else:
        print("Using checksum-verified cached sing-box archive")

    bin_directory.mkdir(parents=True, exist_ok=True)
    target = bin_directory / "sing-box"
    # Extract exactly one expected regular member; never unpack archive paths,
    # links or arbitrary files into the runner's filesystem.
    with tarfile.open(cache, "r:gz") as archive:
        member = archive.getmember(f"{ASSET}/sing-box")
        if not member.isfile() or not 0 < member.size <= MAX_BINARY_BYTES:
            raise RuntimeError("Pinned archive has no valid bounded engine binary")
        source = archive.extractfile(member)
        if source is None:
            raise RuntimeError("Cannot read pinned engine binary")
        with source, tempfile.TemporaryDirectory(prefix="best50-engine-install-", dir=bin_directory) as temporary:
            candidate = Path(temporary) / "sing-box"
            with candidate.open("wb") as stream:
                shutil.copyfileobj(source, stream)
            if candidate.stat().st_size != member.size:
                raise RuntimeError("Incomplete pinned engine extraction")
            candidate.chmod(0o755)
            os.replace(candidate, target)
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--bin-directory", type=Path, required=True)
    arguments = parser.parse_args()
    target = install(arguments.cache, arguments.bin_directory)
    subprocess.run([str(target), "version"], check=True, timeout=15)


if __name__ == "__main__":
    main()
