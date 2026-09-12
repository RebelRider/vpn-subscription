#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import re
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
BUILD_PATH = ROOT / "scripts" / "build.py"

DEFAULT_OUTPUT = ROOT / "output" / "best-local.txt"
DEFAULT_STATUS = ROOT / "output" / "local-status.json"

REGIONAL_REMOTE = "origin"
REGIONAL_BRANCH = "regional"
REGIONAL_SUBSCRIPTION_PATH = "output/best-local.txt"
REGIONAL_STATUS_PATH = "output/local-status.json"

DEFAULT_UPSTREAM_REMOTE = "origin"
DEFAULT_UPSTREAM_BRANCH = "main"
DEFAULT_UPSTREAM_REF = "origin/main"
DEFAULT_UPSTREAM_PATH = "output/qualified-all.txt"

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


def read_links_text(
    text: str,
    description: str,
) -> list[str]:
    links = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("vless://")
    ]

    if not links:
        raise RuntimeError(
            f"No VLESS links found in {description}"
        )

    # Preserve upstream ranking and remove accidental duplicates.
    return list(dict.fromkeys(links))


def read_links(path: Path) -> list[str]:
    if not path.is_file():
        raise RuntimeError(
            f"Input subscription does not exist: {path}"
        )

    return read_links_text(
        path.read_text(),
        str(path),
    )


def run_git(
    *args: str,
) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit {result.returncode}"
        )

        raise RuntimeError(
            "git "
            + " ".join(args)
            + f" failed: {detail}"
        )

    return result.stdout


def upstream_generated_at(
    text: str,
) -> str | None:
    match = re.search(
        r"^# generated:\s*(.+?)\s*$",
        text,
        re.MULTILINE,
    )

    if not match:
        return None

    return match.group(1)


def load_upstream_pool() -> tuple[
    list[str],
    str,
    str | None,
    str,
]:
    print(
        "Fetching latest upstream main..."
    )

    run_git(
        "fetch",
        DEFAULT_UPSTREAM_REMOTE,
        DEFAULT_UPSTREAM_BRANCH,
    )

    upstream_sha = run_git(
        "rev-parse",
        DEFAULT_UPSTREAM_REF,
    ).strip()

    description = (
        f"{DEFAULT_UPSTREAM_REF}:"
        f"{DEFAULT_UPSTREAM_PATH}"
    )

    text = run_git(
        "show",
        description,
    )

    links = read_links_text(
        text,
        description,
    )

    return (
        links,
        upstream_sha,
        upstream_generated_at(text),
        description,
    )


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


def latency_metrics(
    samples: list[float],
) -> dict[str, float | int]:
    if not samples:
        return {
            "samples": 0,
            "median": float("inf"),
            "p95": float("inf"),
        }

    ordered = sorted(samples)

    # Nearest-rank p95.
    p95_index = max(
        0,
        (
            95 * len(ordered) + 99
        ) // 100 - 1,
    )

    return {
        "samples": len(ordered),
        "median": float(
            statistics.median(ordered)
        ),
        "p95": float(
            ordered[p95_index]
        ),
    }


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

    # Local ranking uses only lightweight functional request
    # latency. The 1 MB payload test is deliberately excluded:
    # transfer duration measures throughput/congestion rather
    # than interactive request responsiveness.
    latency_samples: dict[str, list[float]] = {
        link: []
        for link in links
    }

    upstream_rank = {
        link: index
        for index, link in enumerate(
            links,
            1,
        )
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

    for link in survivors:
        latency_samples[link].append(
            passed[link]
        )

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

        for link in survivors:
            latency_samples[link].append(
                passed[link]
            )

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

        round_latency_samples = {
            link: []
            for link in round_survivors
        }

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

            for link in round_survivors:
                round_latency_samples[
                    link
                ].append(
                    passed[link]
                )

            if not round_survivors:
                break

        for link in round_survivors:
            successes[link] += 1

            # Only a complete successful final round contributes
            # latency to ranking. Partial failed rounds do not.
            latency_samples[link].extend(
                round_latency_samples[link]
            )

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

    metrics = {
        link: latency_metrics(
            latency_samples[link]
        )
        for link in qualified
    }

    # Stability is authoritative. Among equally stable nodes,
    # rank by the actual lightweight request latency measured
    # through the forced physical local interface.
    qualified.sort(
        key=lambda link: (
            -successes[link],
            metrics[link]["median"],
            metrics[link]["p95"],
            upstream_rank[link],
        )
    )

    status = {
        "generated_at": (
            datetime.now(timezone.utc)
            .isoformat()
        ),
        "algorithm": (
            "v5-local-network-functional-filter-ranking"
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
                "latency_samples":
                    metrics[link]["samples"],
                "median_latency":
                    metrics[link]["median"],
                "p95_latency":
                    metrics[link]["p95"],
                "upstream_rank":
                    upstream_rank[link],
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
        "# v5.0 — LOCAL NETWORK VERIFIED VLESS",
        "#profile-title: Best Local VPN",
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
        (
            "# local_ranking: "
            "stability, median latency, p95 latency"
        ),
        "#",
        (
            "# Generated from the globally quality-qualified "
            "pool and re-tested through the current "
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


def git_output(
    *args: str,
    cwd: Path = ROOT,
) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            + " ".join(args)
            + "\n"
            + result.stderr.strip()
        )

    return result.stdout.strip()


def validate_generated_result(
    subscription_path: Path,
    status_path: Path,
) -> None:
    if not subscription_path.is_file():
        raise RuntimeError(
            "Generated subscription does not exist: "
            f"{subscription_path}"
        )

    if not status_path.is_file():
        raise RuntimeError(
            "Generated status does not exist: "
            f"{status_path}"
        )

    links = [
        line.strip()
        for line in subscription_path
        .read_text()
        .splitlines()
        if line.startswith("vless://")
    ]

    status = json.loads(
        status_path.read_text()
    )

    qualified = int(
        status["stability"]["qualified"]
    )

    status_links = [
        node["link"]
        for node in status["nodes"]
    ]

    if not links:
        raise RuntimeError(
            "Refusing to publish an empty "
            "regional subscription"
        )

    if len(links) != qualified:
        raise RuntimeError(
            "Subscription/status count mismatch: "
            f"{len(links)} != {qualified}"
        )

    if links != status_links:
        raise RuntimeError(
            "Subscription order does not match "
            "local ranking in status"
        )

    ranks = [
        node["rank"]
        for node in status["nodes"]
    ]

    if ranks != list(
        range(1, len(ranks) + 1)
    ):
        raise RuntimeError(
            "Status ranking is not contiguous"
        )


def qualified_pool_blob(
    ref: str,
) -> str:
    return git_output(
        "rev-parse",
        (
            f"{ref}:"
            f"{DEFAULT_UPSTREAM_PATH}"
        ),
    )


def ensure_input_still_current(
    tested_sha: str,
) -> str:
    print(
        "Checking whether the tested global "
        "candidate pool is still current..."
    )

    git_output(
        "fetch",
        DEFAULT_UPSTREAM_REMOTE,
        DEFAULT_UPSTREAM_BRANCH,
    )

    latest_sha = git_output(
        "rev-parse",
        DEFAULT_UPSTREAM_REF,
    )

    tested_blob = qualified_pool_blob(
        tested_sha
    )

    latest_blob = qualified_pool_blob(
        DEFAULT_UPSTREAM_REF
    )

    print(
        f"Tested main SHA: {tested_sha}"
    )
    print(
        f"Latest main SHA: {latest_sha}"
    )
    print(
        f"Tested pool blob: {tested_blob}"
    )
    print(
        f"Latest pool blob: {latest_blob}"
    )

    if tested_blob != latest_blob:
        raise RuntimeError(
            "STALE LOCAL RESULT: "
            "output/qualified-all.txt changed "
            "while the regional probe was running. "
            "Run the regional probe again."
        )

    return latest_sha


def remote_branch_exists(
    remote: str,
    branch: str,
) -> bool:
    result = subprocess.run(
        [
            "git",
            "ls-remote",
            "--exit-code",
            "--heads",
            remote,
            branch,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode == 0:
        return True

    if result.returncode == 2:
        return False

    raise RuntimeError(
        "Cannot inspect remote regional branch: "
        + result.stderr.strip()
    )


def publish_regional_result(
    subscription_path: Path,
    status_path: Path,
    tested_sha: str,
) -> None:
    subscription_path = (
        subscription_path.resolve()
    )
    status_path = status_path.resolve()

    if subscription_path != DEFAULT_OUTPUT.resolve():
        raise RuntimeError(
            "--publish requires the default "
            "output/best-local.txt path"
        )

    if status_path != DEFAULT_STATUS.resolve():
        raise RuntimeError(
            "--publish requires the default "
            "output/local-status.json path"
        )

    validate_generated_result(
        subscription_path,
        status_path,
    )

    ensure_input_still_current(
        tested_sha
    )

    print()
    print(
        "========================================"
    )
    print(
        "PUBLISH REGIONAL SUBSCRIPTION"
    )
    print(
        "========================================"
    )

    # Refresh both refs immediately before creating
    # the publication worktree.
    git_output(
        "fetch",
        REGIONAL_REMOTE,
        DEFAULT_UPSTREAM_BRANCH,
    )

    regional_exists = remote_branch_exists(
        REGIONAL_REMOTE,
        REGIONAL_BRANCH,
    )

    if regional_exists:
        git_output(
            "fetch",
            REGIONAL_REMOTE,
            REGIONAL_BRANCH,
        )
        base_ref = (
            f"{REGIONAL_REMOTE}/"
            f"{REGIONAL_BRANCH}"
        )
    else:
        base_ref = DEFAULT_UPSTREAM_REF

    with tempfile.TemporaryDirectory(
        prefix="best50-regional-publish-"
    ) as temporary_directory:
        worktree = Path(
            temporary_directory
        )

        # TemporaryDirectory creates the path, while git
        # worktree requires the target path not to exist.
        worktree.rmdir()

        try:
            git_output(
                "worktree",
                "add",
                "--detach",
                str(worktree),
                base_ref,
            )

            output_directory = (
                worktree / "output"
            )

            output_directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            (
                output_directory
                / "best-local.txt"
            ).write_bytes(
                subscription_path.read_bytes()
            )

            (
                output_directory
                / "local-status.json"
            ).write_bytes(
                status_path.read_bytes()
            )

            git_output(
                "add",
                "-f",
                REGIONAL_SUBSCRIPTION_PATH,
                REGIONAL_STATUS_PATH,
                cwd=worktree,
            )

            diff_result = subprocess.run(
                [
                    "git",
                    "diff",
                    "--cached",
                    "--quiet",
                    "--exit-code",
                ],
                cwd=worktree,
                check=False,
                timeout=30,
            )

            if diff_result.returncode == 0:
                print(
                    "Regional subscription is already "
                    "identical to the remote version."
                )
                return

            if diff_result.returncode != 1:
                raise RuntimeError(
                    "Cannot inspect staged regional changes"
                )

            # Recheck the global candidate pool immediately
            # before creating the publication commit.
            ensure_input_still_current(
                tested_sha
            )

            git_output(
                "commit",
                "-m",
                (
                    "chore: update regional "
                    "VPN subscription"
                ),
                cwd=worktree,
            )

            commit_sha = git_output(
                "rev-parse",
                "HEAD",
                cwd=worktree,
            )

            # A normal non-force push is deliberate. If
            # another publisher raced us, Git refuses the
            # update rather than overwriting remote history.
            git_output(
                "push",
                REGIONAL_REMOTE,
                (
                    "HEAD:"
                    f"refs/heads/{REGIONAL_BRANCH}"
                ),
                cwd=worktree,
            )

            print(
                f"Published commit: {commit_sha}"
            )

        finally:
            subprocess.run(
                [
                    "git",
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )

    git_output(
        "fetch",
        REGIONAL_REMOTE,
        REGIONAL_BRANCH,
    )

    remote_ref = (
        f"{REGIONAL_REMOTE}/"
        f"{REGIONAL_BRANCH}"
    )

    remote_subscription_blob = git_output(
        "rev-parse",
        (
            f"{remote_ref}:"
            f"{REGIONAL_SUBSCRIPTION_PATH}"
        ),
    )

    remote_status_blob = git_output(
        "rev-parse",
        (
            f"{remote_ref}:"
            f"{REGIONAL_STATUS_PATH}"
        ),
    )

    local_subscription_blob = git_output(
        "hash-object",
        str(subscription_path),
    )

    local_status_blob = git_output(
        "hash-object",
        str(status_path),
    )

    if (
        remote_subscription_blob
        != local_subscription_blob
        or remote_status_blob
        != local_status_blob
    ):
        raise RuntimeError(
            "Regional publication verification failed"
        )

    print(
        "REGIONAL PUBLICATION VERIFIED: PASS"
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Re-test the globally quality-qualified "
            "VLESS pool through the current local network."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help=(
            "Optional local subscription file for diagnostics. "
            "By default the probe fetches "
            "origin/main:output/qualified-all.txt."
        ),
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
        "--publish",
        action="store_true",
        help=(
            "Publish the successfully generated regional "
            "subscription to the GitHub regional branch."
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

    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()

    if (
        args.publish
        and args.input is not None
    ):
        raise RuntimeError(
            "--publish cannot be used with --input; "
            "publication must be based on the current "
            "origin/main qualified pool"
        )

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
        "REGIONAL LOCAL NETWORK PROBE"
    )
    print(
        "========================================"
    )

    ensure_probe_network(
        args.interface
    )

    upstream_sha: str | None = None
    upstream_generated: str | None = None

    if args.input is not None:
        links = read_links(
            args.input
        )
        input_description = str(
            args.input
        )
        input_mode = "local-file"
    else:
        (
            links,
            upstream_sha,
            upstream_generated,
            input_description,
        ) = load_upstream_pool()
        input_mode = "origin-main-qualified-all"

    print(
        f"Input nodes: {len(links)}"
    )
    print(
        f"Input:       {input_description}"
    )

    if upstream_sha:
        print(
            f"Upstream SHA: "
            f"{upstream_sha}"
        )

    if upstream_generated:
        print(
            f"Upstream generated: "
            f"{upstream_generated}"
        )

    print(
        f"Output:      {args.output}"
    )
    print()

    build = load_build_module()

    # The production probe engine is tuned for GitHub runners and can
    # exceed the default macOS per-process file-descriptor limit when
    # probing the full qualified pool locally.
    #
    # Keep production settings untouched and reduce concurrency only
    # for this local regional validator.
    probe_engine = build.CFG.setdefault(
        "probe_engine",
        {},
    )
    probe_engine["batch_size"] = 16
    probe_engine["parallel_batches"] = 2
    probe_engine["curl_parallel"] = 16

    build.CFG["_probe_default_interface"] = (
        args.interface
    )

    print(
        "Local probe engine: "
        f"batch_size={probe_engine['batch_size']}, "
        f"parallel_batches={probe_engine['parallel_batches']}, "
        f"curl_parallel={probe_engine['curl_parallel']}"
    )

    qualified, status = (
        await run_local_probe(
            build,
            links,
            args.rounds,
            args.minimum_successes,
            input_description,
        )
    )

    status["input"]["mode"] = (
        input_mode
    )
    status["upstream_sha"] = (
        upstream_sha
    )
    status["upstream_generated_at"] = (
        upstream_generated
    )

    status["publication"] = {
        "enabled": bool(args.publish),
        "remote": REGIONAL_REMOTE,
        "branch": REGIONAL_BRANCH,
        "subscription_path":
            REGIONAL_SUBSCRIPTION_PATH,
        "status_path":
            REGIONAL_STATUS_PATH,
    }

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

    if upstream_sha:
        print(
            f"Upstream SHA:  "
            f"{upstream_sha}"
        )

    if upstream_generated:
        print(
            f"Upstream time: "
            f"{upstream_generated}"
        )

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

    validate_generated_result(
        args.output,
        args.status,
    )

    print(
        "LOCAL GENERATED RESULT VALIDATION: PASS"
    )

    if args.publish:
        if not upstream_sha:
            raise RuntimeError(
                "Cannot publish without an "
                "origin/main upstream SHA"
            )

        publish_regional_result(
            args.output,
            args.status,
            upstream_sha,
        )

        print()
        print(
            "Regional subscription URL:"
        )
        print(
            "https://raw.githubusercontent.com/"
            "RebelRider/vpn-subscription/"
            "regional/output/best-local.txt"
        )

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
