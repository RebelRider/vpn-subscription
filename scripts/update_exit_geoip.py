#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import os
import subprocess
import tempfile
import time
from pathlib import Path


DATABASES = {
    "ipv4": (
        "https://github.com/sapics/ip-location-db/"
        "releases/download/latest/"
        "dbip-city-ipv4.csv.gz"
    ),
    "ipv6": (
        "https://github.com/sapics/ip-location-db/"
        "releases/download/latest/"
        "dbip-city-ipv6.csv.gz"
    ),
}


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--state-dir",
        type=Path,
        default=(
            Path.home()
            / "Library"
            / "Application Support"
            / "best50-vpn"
        ),
    )

    parser.add_argument(
        "--max-age-days",
        type=float,
        default=7.0,
    )

    return parser.parse_args()


def validate_database(
    path: Path,
    version: int,
) -> None:
    checked = 0
    with_city = 0

    with gzip.open(
        path,
        "rt",
        encoding="utf-8",
        newline="",
    ) as handle:

        for row in csv.reader(
            handle
        ):
            if len(row) < 6:
                raise RuntimeError(
                    "Malformed DB-IP row"
                )

            start = (
                ipaddress.ip_address(
                    row[0].strip()
                )
            )

            end = (
                ipaddress.ip_address(
                    row[1].strip()
                )
            )

            if (
                start.version != version
                or end.version != version
            ):
                raise RuntimeError(
                    "Unexpected IP family"
                )

            if int(start) > int(end):
                raise RuntimeError(
                    "Reversed DB-IP range"
                )

            if row[5].strip():
                with_city += 1

            checked += 1

            if checked >= 2000:
                break

    if checked < 100:
        raise RuntimeError(
            "City database is suspiciously small"
        )

    if with_city == 0:
        raise RuntimeError(
            "No city records found"
        )


def download(
    url: str,
    destination: Path,
) -> None:
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.NamedTemporaryFile(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=destination.parent,
        delete=False,
    ) as handle:
        temporary = Path(
            handle.name
        )

    try:
        result = subprocess.run(
            [
                "curl",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--retry",
                "3",
                "--retry-delay",
                "2",
                "--output",
                str(temporary),
                url,
            ],
            check=False,
            timeout=180,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"curl exit {result.returncode}"
            )

        with gzip.open(
            temporary,
            "rb",
        ) as stream:
            while stream.read(
                1024 * 1024
            ):
                pass

        os.replace(
            temporary,
            destination,
        )

    finally:
        temporary.unlink(
            missing_ok=True
        )


def main() -> int:
    args = parse_args()

    directory = (
        args.state_dir
        / "geoip"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    max_age = (
        max(
            args.max_age_days,
            0.0,
        )
        * 86400.0
    )

    now = time.time()

    for family, url in DATABASES.items():
        version = (
            4
            if family == "ipv4"
            else 6
        )

        destination = (
            directory
            / f"dbip-city-{family}.csv.gz"
        )

        fresh = (
            destination.is_file()
            and (
                now
                - destination.stat().st_mtime
            ) < max_age
        )

        if fresh:
            print(
                f"{family}: cache fresh: "
                f"{destination}"
            )
            continue

        previous_exists = (
            destination.is_file()
        )

        print(
            f"{family}: refreshing..."
        )

        try:
            with tempfile.TemporaryDirectory(
                prefix="best50-geoip-"
            ) as td:

                staged = (
                    Path(td)
                    / destination.name
                )

                download(
                    url,
                    staged,
                )

                validate_database(
                    staged,
                    version,
                )

                os.replace(
                    staged,
                    destination,
                )

            print(
                f"{family}: updated"
            )

        except Exception as exc:
            if previous_exists:
                print(
                    f"WARNING: {family} refresh failed; "
                    f"keeping cached DB: {exc}"
                )
            else:
                print(
                    f"WARNING: {family} unavailable; "
                    f"neutral presentation fallback: {exc}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
