#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent

sys.path.insert(0, str(SCRIPT_DIR))

import build


def download(url: str) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "Best50-Source-Recon/1.0",
        },
    )

    with urlopen(
        request,
        timeout=120,
    ) as response:
        return response.read().decode(
            "utf-8",
            errors="replace",
        )


def extract_subscription(
    text: str,
) -> tuple[list[str], str]:
    direct = build.extract_vless(text)

    if direct:
        return direct, "plain"

    compact = "".join(
        line.strip()
        for line in text.splitlines()
        if line.strip()
    )

    if not compact:
        return [], "empty"

    try:
        padded = compact + "=" * (
            (-len(compact)) % 4
        )

        decoded = base64.b64decode(
            padded,
            validate=False,
        ).decode(
            "utf-8",
            errors="replace",
        )

        links = build.extract_vless(decoded)

        if links:
            return links, "base64"

    except Exception:
        pass

    return [], "unknown"


def structural_fingerprints(
    links: list[str],
) -> tuple[set[str], int]:
    fingerprints: set[str] = set()
    rejected = 0

    for link in links:
        try:
            node = build.parse_vless(link)
            fingerprint = (
                build.normalized_fingerprint(
                    node
                )
            )
        except Exception:
            rejected += 1
            continue

        fingerprints.add(fingerprint)

    return fingerprints, rejected


async def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Measure the marginal value of a VLESS "
            "source against the configured production "
            "source set."
        )
    )

    parser.add_argument(
        "--name",
        required=True,
    )

    parser.add_argument(
        "--url",
        required=True,
    )

    parser.add_argument(
        "--output-dir",
        default="/tmp/best50-source-recon",
    )

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_name = "".join(
        char.lower()
        if char.isalnum()
        else "-"
        for char in args.name
    ).strip("-")

    while "--" in safe_name:
        safe_name = safe_name.replace(
            "--",
            "-",
        )

    target_path = (
        output_dir
        / f"{safe_name}-target-new.txt"
    )

    metadata_path = (
        output_dir
        / f"{safe_name}-recon.json"
    )

    raw_path = (
        output_dir
        / f"{safe_name}-source.txt"
    )

    print("=" * 72)
    print(f"SOURCE RECON: {args.name}")
    print("=" * 72)

    # Country filtering is security-sensitive.
    # Validate/cache the complete GeoIP database first.
    build._load_geoip_databases()

    print()
    print("Downloading candidate source...")
    print(args.url)

    source_text = await asyncio.to_thread(
        download,
        args.url,
    )

    raw_path.write_text(
        source_text,
        encoding="utf-8",
    )

    incoming, encoding = (
        extract_subscription(
            source_text
        )
    )

    print(
        f"Source encoding: {encoding}"
    )
    print(
        f"Extracted VLESS: {len(incoming)}"
    )

    print()
    print(
        "Building current production baseline..."
    )

    baseline_links: list[str] = []
    baseline_failures: list[dict] = []

    for source in build.CFG.get(
        "sources",
        [],
    ):
        name = source.get(
            "name",
            "unknown",
        )
        url = source.get(
            "url",
            "",
        )

        print(
            f"  {name}",
            end="",
            flush=True,
        )

        try:
            text = await asyncio.to_thread(
                build.fetch,
                url,
            )

            links = build.extract_vless(
                text
            )

        except Exception as error:
            print(
                f" -> ERROR: {error}"
            )

            baseline_failures.append(
                {
                    "name": name,
                    "url": url,
                    "error": str(error),
                }
            )
            continue

        baseline_links.extend(links)

        print(
            f" -> {len(links)}"
        )

    baseline_structural, baseline_rejected = (
        structural_fingerprints(
            baseline_links
        )
    )

    exact_unique = list(
        dict.fromkeys(
            link.strip()
            for link in incoming
            if link.strip()
        )
    )

    structural_seen: set[str] = set()

    parseable = 0
    parser_rejected = 0
    internal_duplicates = 0
    structural_overlap = 0

    marginal: list[
        tuple[str, dict]
    ] = []

    reject_reasons: dict[str, int] = {}

    for link in exact_unique:
        try:
            node = build.parse_vless(
                link
            )

            fingerprint = (
                build.normalized_fingerprint(
                    node
                )
            )

        except Exception as error:
            parser_rejected += 1

            reason = str(error)

            reject_reasons[reason] = (
                reject_reasons.get(
                    reason,
                    0,
                )
                + 1
            )

            continue

        parseable += 1

        if fingerprint in structural_seen:
            internal_duplicates += 1
            continue

        structural_seen.add(
            fingerprint
        )

        if fingerprint in baseline_structural:
            structural_overlap += 1
            continue

        marginal.append(
            (link, node)
        )

    print()
    print("Marginal analysis:")
    print(
        f"  baseline raw:          "
        f"{len(baseline_links)}"
    )
    print(
        f"  baseline structural:   "
        f"{len(baseline_structural)}"
    )
    print(
        f"  source raw:            "
        f"{len(incoming)}"
    )
    print(
        f"  exact unique:          "
        f"{len(exact_unique)}"
    )
    print(
        f"  parseable:             "
        f"{parseable}"
    )
    print(
        f"  parser rejected:       "
        f"{parser_rejected}"
    )
    print(
        f"  structural unique:     "
        f"{len(structural_seen)}"
    )
    print(
        f"  internal duplicates:   "
        f"{internal_duplicates}"
    )
    print(
        f"  structural overlap:    "
        f"{structural_overlap}"
    )
    print(
        f"  STRUCTURAL NEW:        "
        f"{len(marginal)}"
    )

    if marginal:
        qualified = (
            await build.classify_countries_batch(
                marginal
            )
        )
    else:
        qualified = []

    countries: dict[str, int] = {}
    methods: dict[str, int] = {}

    for node in qualified:
        country = node.get(
            "country",
            "XX",
        )

        method = node.get(
            "country_method",
            "unknown",
        )

        countries[country] = (
            countries.get(
                country,
                0,
            )
            + 1
        )

        methods[method] = (
            methods.get(
                method,
                0,
            )
            + 1
        )

    target_path.write_text(
        "".join(
            node["link"].rstrip()
            + "\n"
            for node in qualified
        ),
        encoding="utf-8",
    )

    report = {
        "source": args.name,
        "url": args.url,
        "encoding": encoding,
        "baseline": {
            "raw": len(
                baseline_links
            ),
            "structural": len(
                baseline_structural
            ),
            "parser_rejected": (
                baseline_rejected
            ),
            "fetch_failures": (
                baseline_failures
            ),
        },
        "candidate": {
            "raw": len(incoming),
            "exact_unique": len(
                exact_unique
            ),
            "parseable": parseable,
            "parser_rejected": (
                parser_rejected
            ),
            "structural_unique": len(
                structural_seen
            ),
            "internal_structural_duplicates":
                internal_duplicates,
            "structural_overlap":
                structural_overlap,
            "structural_new": len(
                marginal
            ),
            "parser_reject_reasons":
                dict(
                    sorted(
                        reject_reasons.items(),
                        key=lambda item: (
                            -item[1],
                            item[0],
                        ),
                    )
                ),
        },
        "target_country_new": len(
            qualified
        ),
        "countries": countries,
        "country_methods": methods,
        "files": {
            "raw": str(raw_path),
            "target": str(
                target_path
            ),
        },
    }

    metadata_path.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print()
    print("=" * 72)
    print("RESULT")
    print("=" * 72)

    print(
        f"Structural new:    "
        f"{len(marginal)}"
    )
    print(
        f"Target-country new:"
        f" {len(qualified)}"
    )
    print(
        f"Countries:         "
        f"{countries}"
    )
    print(
        f"Methods:           "
        f"{methods}"
    )

    print()
    print(
        f"Target pool: {target_path}"
    )
    print(
        f"Report:      {metadata_path}"
    )

    # A zero-yield source is a valid diagnostic result,
    # not an execution error.
    return 0


if __name__ == "__main__":
    raise SystemExit(
        asyncio.run(main())
    )
