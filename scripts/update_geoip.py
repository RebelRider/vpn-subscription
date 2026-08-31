#!/usr/bin/env python3

from __future__ import annotations

import csv
import ipaddress
import os
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "geoip"

# sapics/ip-location-db server-country:
# daily PDDL database optimized for physical server / relay location.
BASE = (
    "https://raw.githubusercontent.com/"
    "sapics/ip-location-db/main/server-country/"
)

FILES = {
    "server-country-ipv4.csv":
        BASE + "server-country-ipv4.csv",
    "server-country-ipv6.csv":
        BASE + "server-country-ipv6.csv",
}


def download(
    url: str,
    destination: Path,
    attempts: int = 4,
) -> None:
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    tmp = destination.with_suffix(
        destination.suffix + ".tmp"
    )

    last_error: Exception | None = None

    for attempt in range(
        1,
        attempts + 1,
    ):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent":
                        "Best50Builder-GeoIP/4.4",
                    "Accept":
                        "text/csv,application/octet-stream,*/*",
                },
            )

            print(
                f"Downloading {destination.name} "
                f"(attempt {attempt}/{attempts})..."
            )

            with urllib.request.urlopen(
                request,
                timeout=90,
            ) as response:
                with tmp.open("wb") as output:
                    while True:
                        block = response.read(
                            1024 * 1024
                        )

                        if not block:
                            break

                        output.write(block)

            if tmp.stat().st_size < 1024:
                raise RuntimeError(
                    f"{destination.name} is unexpectedly small: "
                    f"{tmp.stat().st_size} bytes"
                )

            os.replace(
                tmp,
                destination,
            )

            return

        except Exception as error:
            last_error = error

            try:
                tmp.unlink()
            except FileNotFoundError:
                pass

            if attempt < attempts:
                delay = 2 ** (
                    attempt - 1
                )

                print(
                    f"WARNING: {error}; "
                    f"retrying in {delay}s",
                    file=sys.stderr,
                )

                time.sleep(delay)

    raise RuntimeError(
        f"Failed downloading {destination.name}: "
        f"{last_error}"
    )


def validate(
    path: Path,
    expected_version: int,
) -> int:
    rows = 0
    previous_start = -1

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.reader(handle)

        for row in reader:
            if not row:
                continue

            if len(row) < 3:
                raise RuntimeError(
                    f"Invalid row in {path.name}: "
                    f"{row!r}"
                )

            start_raw = row[0].strip()
            end_raw = row[1].strip()
            country = row[2].strip().upper()

            start_ip = ipaddress.ip_address(
                start_raw
            )

            end_ip = ipaddress.ip_address(
                end_raw
            )

            if (
                start_ip.version
                != expected_version
                or end_ip.version
                != expected_version
            ):
                raise RuntimeError(
                    f"Wrong IP version in {path.name}: "
                    f"{start_raw},{end_raw}"
                )

            start_value = int(
                start_ip
            )

            end_value = int(
                end_ip
            )

            if start_value > end_value:
                raise RuntimeError(
                    f"Invalid range in {path.name}: "
                    f"{start_raw},{end_raw}"
                )

            if start_value < previous_start:
                raise RuntimeError(
                    f"Database is not sorted: "
                    f"{path.name}"
                )

            previous_start = start_value

            if (
                len(country) != 2
                and country != "XX"
            ):
                raise RuntimeError(
                    f"Invalid country code in "
                    f"{path.name}: {country!r}"
                )

            rows += 1

    if rows < 1000:
        raise RuntimeError(
            f"{path.name} has too few rows: "
            f"{rows}"
        )

    return rows


def main() -> int:
    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for filename, url in FILES.items():
        destination = (
            DATA_DIR / filename
        )

        download(
            url,
            destination,
        )

    ipv4_rows = validate(
        DATA_DIR
        / "server-country-ipv4.csv",
        4,
    )

    ipv6_rows = validate(
        DATA_DIR
        / "server-country-ipv6.csv",
        6,
    )

    print()
    print(
        "Local GeoIP database ready:"
    )
    print(
        f"IPv4 ranges: {ipv4_rows}"
    )
    print(
        f"IPv6 ranges: {ipv6_rows}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
