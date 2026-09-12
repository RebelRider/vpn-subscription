#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
BUILD_PATH = ROOT / "scripts" / "build.py"

DEFAULT_INPUT = ROOT / "output" / "best50.txt"
DEFAULT_OUTPUT = ROOT / "output" / "best-local.txt"
DEFAULT_STATUS = ROOT / "output" / "local-status.json"

ALLOWED_COUNTRIES = {"US", "DE", "PL", "NL"}


def load_build_module():
    spec = importlib.util.spec_from_file_location(
        "best50_build",
        BUILD_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Cannot import build module: {BUILD_PATH}"
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    required = (
        "CFG",
        "_v5_probe_gate",
        "run_probe_batches",
        "parse_vless",
        "vless_to_singbox",
    )

    missing = [
        name
        for name in required
        if not hasattr(module, name)
    ]

    if missing:
        raise RuntimeError(
            "scripts/build.py is missing required API: "
            + ", ".join(missing)
        )

    return module


def read_links(path: Path) -> list[str]:
    if not path.is_file():
        raise RuntimeError(
            f"Input subscription does not exist: {path}"
        )

    links = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip().startswith("vless://")
    ]

    if not links:
        raise RuntimeError(
            f"No VLESS links found in {path}"
        )

    # Preserve upstream ranking and remove accidental duplicates.
    return list(dict.fromkeys(links))


def country_from_link(link: str) -> str:
    country = unquote(
        urlsplit(link).fragment
    ).strip().upper()

    if country not in ALLOWED_COUNTRIES:
        return "XX"

    return country


def route_interface(
    destination: str = "1.1.1.1",
) -> str | None:
    try:
        result = subprocess.run(
            [
                "route",
                "-n",
                "get",
                destination,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None

    match = re.search(
        r"^\s*interface:\s*(\S+)",
        result.stdout,
        re.MULTILINE,
    )

    if not match:
        return None

    return match.group(1)


def ensure_probe_network(
    forced_interface: str,
) -> None:
    system_interface = route_interface()

    print(
        "System route interface:",
        system_interface or "unknown",
    )

    print(
        "Probe forced interface:",
        forced_interface,
    )

    try:
        result = subprocess.run(
            [
                "ifconfig",
                forced_interface,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        raise RuntimeError(
            "Cannot inspect probe interface "
            f"{forced_interface!r}: {exc}"
        )

    if result.returncode != 0:
        raise RuntimeError(
            "Probe interface does not exist: "
            f"{forced_interface}"
        )

    ipv4_match = re.search(
        r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)",
        result.stdout,
        re.MULTILINE,
    )

    if not ipv4_match:
        raise RuntimeError(
            "Probe interface has no IPv4 address: "
            f"{forced_interface}"
        )

    print(
        "Probe interface IPv4:",
        ipv4_match.group(1),
    )

    if (
        system_interface
        and system_interface.startswith("utun")
    ):
        print(
            "Active system VPN detected; "
            "probe VLESS outbounds will be forced through "
            f"{forced_interface}."
        )


async def run_gate(
    build,
    links: list[str],
    gate: dict,
    prefix: str,
) -> dict[str, float]:
    return await build._v5_probe_gate(
        links,
        f"{prefix}-{gate['name']}",
        gate["url"],
        gate.get("request_timeout"),
        gate.get(
            "accepted_status_pattern",
            r"^[23]\d\d$",
        ),
    )


async def run_local_probe(
    build,
    links: list[str],
    final_rounds: int,
    minimum_successes: int,
    input_description: str,
) -> tuple[
    list[str],
    dict,
]:
    functional = build.CFG.get(
        "functional_tests",
        {},
    )

    if not functional.get(
        "enabled",
        True,
    ):
        raise RuntimeError(
            "functional_tests are disabled in config.json"
        )

    counts: dict[str, int] = {
        "input": len(links),
    }

    # -----------------------------------------------------
    # Stage 1: exact same preliminary gate as production v5
    # -----------------------------------------------------

    preliminary = functional["preliminary"]

    passed = await run_gate(
        build,
        links,
        preliminary,
        "local-preliminary",
    )

    survivors = [
        link
        for link in links
        if link in passed
    ]

    counts[
        f"preliminary_{preliminary['name']}"
    ] = len(survivors)

    # -----------------------------------------------------
    # Stage 2: production mandatory functional gates
    # -----------------------------------------------------

    gate_counts = {}

    for gate in functional.get(
        "mandatory_gates",
        [],
    ):
        passed = await run_gate(
            build,
            survivors,
            gate,
            "local-mandatory",
        )

        survivors = [
            link
            for link in survivors
            if link in passed
        ]

        gate_counts[gate["name"]] = len(
            survivors
        )

    # -----------------------------------------------------
    # Stage 3: mandatory real payload
    # -----------------------------------------------------

    payload = functional.get(
        "payload_gate",
        {},
    )

    if payload.get("enabled", True):
        passed = await run_gate(
            build,
            survivors,
            payload,
            "local-payload",
        )

        survivors = [
            link
            for link in survivors
            if link in passed
        ]

        gate_counts[payload["name"]] = len(
            survivors
        )

    first_pass_survivors = list(
        survivors
    )

    # -----------------------------------------------------
    # Stage 4: local stability confirmation.
    #
    # Every round is successful for a node only if ALL
    # production final gates succeed in that round.
    # -----------------------------------------------------

    final_gates = functional.get(
        "final_gates",
        [],
    )

    successes = {
        link: 0
        for link in first_pass_survivors
    }

    round_counts: list[int] = []

    for round_index in range(
        1,
        final_rounds + 1,
    ):
        round_survivors = list(
            first_pass_survivors
        )

        print()
        print(
            "========================================"
        )
        print(
            f"LOCAL FINAL ROUND "
            f"{round_index}/{final_rounds}"
        )
        print(
            "========================================"
        )

        for gate in final_gates:
            passed = await run_gate(
                build,
                round_survivors,
                gate,
                (
                    f"local-final-"
                    f"r{round_index}"
                ),
            )

            round_survivors = [
                link
                for link in round_survivors
                if link in passed
            ]

            if not round_survivors:
                break

        for link in round_survivors:
            successes[link] += 1

        round_counts.append(
            len(round_survivors)
        )

        print(
            f"LOCAL FINAL ROUND "
            f"{round_index}: "
            f"{len(round_survivors)}/"
            f"{len(first_pass_survivors)} "
            "passed complete suite"
        )

    qualified = [
        link
        for link in links
        if (
            link in successes
            and successes[link]
            >= minimum_successes
        )
    ]

    status = {
        "generated_at": (
            datetime.now(timezone.utc)
            .isoformat()
        ),
        "algorithm": (
            "v5-local-network-functional-filter"
        ),
        "input": {
            "path": input_description,
            "nodes": len(links),
        },
        "network": {
            "system_route_interface": route_interface(),
            "probe_default_interface": str(
                build.CFG.get(
                    "_probe_default_interface",
                    "",
                )
            ),
        },
        "gates": {
            "preliminary": {
                preliminary["name"]:
                    counts[
                        f"preliminary_{preliminary['name']}"
                    ],
            },
            "mandatory": gate_counts,
        },
        "stability": {
            "rounds": final_rounds,
            "minimum_successes":
                minimum_successes,
            "first_pass_survivors":
                len(first_pass_survivors),
            "round_survivors":
                round_counts,
            "qualified":
                len(qualified),
        },
        "countries": dict(
            Counter(
                country_from_link(link)
                for link in qualified
            )
        ),
        "nodes": [
            {
                "rank":
                    index + 1,
                "country":
                    country_from_link(link),
                "successful_final_rounds":
                    successes.get(link, 0),
                "link":
                    link,
            }
            for index, link
            in enumerate(qualified)
        ],
    }

    return qualified, status


def write_subscription(
    output_path: Path,
    links: list[str],
    status: dict,
) -> None:
    generated = datetime.now(
        timezone.utc
    ).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    lines = [
        "# Best50 v5.0 — LOCAL NETWORK VERIFIED VLESS",
        "#profile-title: Best50 Local",
        "#profile-update-interval: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#ping-type: proxy",
        (
            "#check-url-via-proxy: "
            "https://www.gstatic.com/generate_204"
        ),
        "#subscriptions-sort-type: ping",
        f"# generated: {generated}",
        "#",
        (
            "# Local filtering: "
            "gstatic + cloudflare + youtube + "
            "chatgpt + payload-1mb"
        ),
        (
            "# Local final stability: "
            f"{status['stability']['minimum_successes']}/"
            f"{status['stability']['rounds']} "
            "complete rounds required"
        ),
        (
            "# upstream_nodes: "
            f"{status['input']['nodes']}"
        ),
        (
            "# local_qualified: "
            f"{len(links)}"
        ),
        "#",
        (
            "# Generated from the globally filtered "
            "Best50 and re-tested through the current "
            "local network."
        ),
        "#",
    ]

    lines.extend(links)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    temp.write_text(
        "\n".join(lines) + "\n"
    )

    temp.replace(output_path)


def write_status(
    path: Path,
    status: dict,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp.write_text(
        json.dumps(
            status,
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )

    temp.replace(path)


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Re-test the globally selected Best50 "
            "through the current local network."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    parser.add_argument(
        "--status",
        type=Path,
        default=DEFAULT_STATUS,
    )

    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help=(
            "Number of local final stability rounds "
            "(default: 3)"
        ),
    )

    parser.add_argument(
        "--minimum-successes",
        type=int,
        default=2,
        help=(
            "Required complete final rounds "
            "(default: 2)"
        ),
    )

    parser.add_argument(
        "--interface",
        default="en0",
        help=(
            "Physical interface used for probe outbound "
            "connections (default: en0)"
        ),
    )

    parser.add_argument(
        "--allow-tunnel",
        action="store_true",
        help=(
            "Allow execution while a utun/PPP/IPsec "
            "route is active. Normally do not use this."
        ),
    )

    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()

    if args.rounds < 1:
        raise RuntimeError(
            "--rounds must be >= 1"
        )

    if (
        args.minimum_successes < 1
        or args.minimum_successes
        > args.rounds
    ):
        raise RuntimeError(
            "--minimum-successes must be between "
            "1 and --rounds"
        )

    print(
        "========================================"
    )
    print(
        "BEST50 LOCAL NETWORK PROBE"
    )
    print(
        "========================================"
    )

    ensure_probe_network(
        args.interface
    )

    links = read_links(
        args.input
    )

    print(
        f"Input nodes: {len(links)}"
    )
    print(
        f"Input:       {args.input}"
    )
    print(
        f"Output:      {args.output}"
    )
    print()

    build = load_build_module()

    build.CFG["_probe_default_interface"] = (
        args.interface
    )

    qualified, status = (
        await run_local_probe(
            build,
            links,
            args.rounds,
            args.minimum_successes,
            str(args.input),
        )
    )

    write_subscription(
        args.output,
        qualified,
        status,
    )

    write_status(
        args.status,
        status,
    )

    print()
    print(
        "========================================"
    )
    print(
        "LOCAL PROBE COMPLETE"
    )
    print(
        "========================================"
    )

    print(
        f"Input:               "
        f"{len(links)}"
    )

    preliminary = status[
        "gates"
    ]["preliminary"]

    for name, count in preliminary.items():
        print(
            f"{name:20s} "
            f"{count}"
        )

    for name, count in status[
        "gates"
    ]["mandatory"].items():
        print(
            f"{name:20s} "
            f"{count}"
        )

    print(
        f"First-pass survivors: "
        f"{status['stability']['first_pass_survivors']}"
    )

    for index, count in enumerate(
        status[
            "stability"
        ]["round_survivors"],
        1,
    ):
        print(
            f"Final round {index}:      "
            f"{count}"
        )

    print(
        f"LOCAL QUALIFIED:     "
        f"{len(qualified)}"
    )

    print(
        "Countries:           "
        + ", ".join(
            f"{country}={count}"
            for country, count
            in sorted(
                status["countries"].items()
            )
        )
    )

    print()
    print(
        f"Subscription: {args.output}"
    )
    print(
        f"Status:       {args.status}"
    )

    if not qualified:
        print(
            "WARNING: no locally qualified nodes."
        )
        return 2

    return 0


def main() -> int:
    try:
        return asyncio.run(
            async_main()
        )
    except KeyboardInterrupt:
        print(
            "\nInterrupted.",
            file=sys.stderr,
        )
        return 130
    except Exception as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
