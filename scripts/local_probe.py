#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import csv
import gzip
import hashlib
import math
import fcntl
import time
import importlib.util
import ipaddress
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


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
DEFAULT_UPSTREAM_PATH = "output/best50.txt"

ALLOWED_COUNTRIES = {"US", "DE", "PL", "NL"}

STATE_DIR = (
    Path.home()
    / "Library"
    / "Application Support"
    / "best50-vpn"
)

CITY_DB_IPV4 = Path(
    os.environ.get(
        "BEST50_CITY_DB_IPV4",
        str(
            STATE_DIR
            / "geoip"
            / "dbip-city-ipv4.csv.gz"
        ),
    )
)

CITY_DB_IPV6 = Path(
    os.environ.get(
        "BEST50_CITY_DB_IPV6",
        str(
            STATE_DIR
            / "geoip"
            / "dbip-city-ipv6.csv.gz"
        ),
    )
)

EXIT_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

# Final best-local publication policy.
#
# These countries are checked against the ACTUAL VPN exit,
# not the source label, endpoint IP, hostname, or upstream
# country classification.
ALLOWED_ACTUAL_EXIT_COUNTRIES = frozenset({
    "GB",
    "US",
    "DE",
    "NL",
    "PL",
})

# best-local is deliberately a small high-confidence set.
# Never pad the subscription with weaker nodes merely to
# reach this number.
MAX_LOCAL_PUBLISHED_NODES = 12
MAX_LOCAL_MEDIAN_LATENCY_MS = 500.0


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


def load_protocols():
    spec = importlib.util.spec_from_file_location("bestlocal_protocols", ROOT / "scripts" / "protocols.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def read_links_text(
    text: str,
    description: str,
) -> list[str]:
    if len(text.encode()) > 1024 * 1024:
        raise RuntimeError("Subscription exceeds size limit")
    entries = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not entries or len(entries) > 50 or any(entry.split(":", 1)[0].lower() not in load_protocols().SUPPORTED_SCHEMES or len(entry) > 16384 for entry in entries):
        raise RuntimeError("Best50 must contain 1..50 Happ-compatible configurations and comments only")
    return list(dict.fromkeys(entries))


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


def country_flag(
    country: str | None,
) -> str:
    country = (
        country or ""
    ).strip().upper()

    if not re.fullmatch(
        r"[A-Z]{2}",
        country,
    ):
        return "🌐"

    return "".join(
        chr(
            0x1F1E6
            + ord(letter)
            - ord("A")
        )
        for letter in country
    )


def normalize_city(
    city: str | None,
) -> str:
    city = (
        city or ""
    ).strip()

    if not city:
        return ""

    city = re.sub(
        r"\s+\([^()]+\)\s*$",
        "",
        city,
    ).strip()

    return city


def presentation_label(
    rank: int,
    exit_country: str | None = None,
    exit_city: str | None = None,
) -> str:
    if rank < 1:
        raise ValueError(
            f"Invalid rank: {rank}"
        )

    country = (
        exit_country or ""
    ).strip().upper()

    city = normalize_city(
        exit_city
    )

    if not re.fullmatch(
        r"[A-Z]{2}",
        country,
    ):
        return f"🌐 | {rank}"

    prefix = (
        f"{country_flag(country)} "
        f"{country}"
    )

    if city:
        return (
            f"{prefix} | "
            f"{city} | "
            f"{rank}"
        )

    return (
        f"{prefix} | "
        f"{rank}"
    )


def published_link(
    link: str,
    rank: int,
    exit_country: str | None = None,
    exit_city: str | None = None,
) -> str:
    """
    Build presentation-only URI fragment.

    Final user-facing geography comes only from the actual VPN
    egress connection. Source/endpoint country is not used as a
    presentation fallback.

    Failure to determine egress geography does not disqualify an
    otherwise working node; it gets a neutral globe label.
    """
    label = presentation_label(
        rank,
        exit_country,
        exit_city,
    )

    return load_protocols().relabel(link, label)

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



def _parse_cloudflare_trace(
    payload: bytes,
) -> dict[str, str] | None:
    values: dict[str, str] = {}

    for raw_line in payload.decode(
        errors="ignore",
    ).splitlines():

        if "=" not in raw_line:
            continue

        key, value = raw_line.split(
            "=",
            1,
        )

        values[
            key.strip()
        ] = value.strip()

    raw_ip = values.get(
        "ip",
        "",
    )

    if not raw_ip:
        return None

    try:
        address = (
            ipaddress.ip_address(
                raw_ip
            )
        )
    except ValueError:
        return None

    country = values.get(
        "loc",
        "",
    ).strip().upper()

    if not re.fullmatch(
        r"[A-Z]{2}",
        country,
    ):
        country = ""

    return {
        "exit_ip": str(address),
        "trace_country": country,
    }


def _lookup_city_database(
    database_path: Path,
    addresses: list[str],
) -> dict[str, dict]:
    if (
        not database_path.is_file()
        or not addresses
    ):
        return {}

    targets = []

    for raw_address in addresses:
        try:
            address = (
                ipaddress.ip_address(
                    raw_address
                )
            )
        except ValueError:
            continue

        targets.append(
            (
                int(address),
                str(address),
                address.version,
            )
        )

    if not targets:
        return {}

    versions = {
        item[2]
        for item in targets
    }

    if len(versions) != 1:
        raise ValueError(
            "Mixed IP families in one DB lookup"
        )

    version = next(
        iter(versions)
    )

    ordered_targets = sorted(
        (
            value,
            text,
        )
        for value, text, _
        in targets
    )

    result: dict[str, dict] = {}
    target_index = 0

    try:
        handle = gzip.open(
            database_path,
            "rt",
            encoding="utf-8",
            newline="",
        )
    except OSError:
        return {}

    with handle:
        reader = csv.reader(
            handle
        )

        for row in reader:
            if len(row) < 6:
                continue

            try:
                start_ip = (
                    ipaddress.ip_address(
                        row[0].strip()
                    )
                )

                end_ip = (
                    ipaddress.ip_address(
                        row[1].strip()
                    )
                )
            except ValueError:
                continue

            if (
                start_ip.version != version
                or end_ip.version != version
            ):
                continue

            start_value = int(
                start_ip
            )

            end_value = int(
                end_ip
            )

            while (
                target_index
                < len(ordered_targets)
                and ordered_targets[
                    target_index
                ][0] < start_value
            ):
                target_index += 1

            while (
                target_index
                < len(ordered_targets)
                and start_value
                <= ordered_targets[
                    target_index
                ][0]
                <= end_value
            ):
                _, target_text = (
                    ordered_targets[
                        target_index
                    ]
                )

                result[
                    target_text
                ] = {
                    "db_country":
                        row[2]
                        .strip()
                        .upper(),
                    "region":
                        row[3]
                        .strip(),
                    "region2":
                        row[4]
                        .strip(),
                    "city":
                        normalize_city(
                            row[5]
                        ),
                }

                target_index += 1

            if (
                target_index
                >= len(
                    ordered_targets
                )
            ):
                break

    return result


def apply_exit_geography(
    status: dict,
    metadata: dict[str, dict],
) -> None:
    ipv4: list[str] = []
    ipv6: list[str] = []

    for item in metadata.values():
        raw_ip = item.get(
            "exit_ip",
            "",
        )

        if not raw_ip:
            continue

        try:
            address = ipaddress.ip_address(
                raw_ip
            )
        except ValueError:
            continue

        if address.version == 4:
            ipv4.append(str(address))
        else:
            ipv6.append(str(address))

    city_lookup = {}

    try:
        city_lookup.update(
            _lookup_city_database(
                CITY_DB_IPV4,
                list(dict.fromkeys(ipv4)),
            )
        )
    except Exception as exc:
        print(
            "WARNING: IPv4 exit-city lookup failed: "
            f"{exc}"
        )

    try:
        city_lookup.update(
            _lookup_city_database(
                CITY_DB_IPV6,
                list(dict.fromkeys(ipv6)),
            )
        )
    except Exception as exc:
        print(
            "WARNING: IPv6 exit-city lookup failed: "
            f"{exc}"
        )

    exit_country_counts = Counter()
    rejected_country_counts = Counter()

    complete = 0
    country_only = 0
    unknown = 0
    rejected_country = 0

    allowed_nodes: list[dict] = []

    for node in status.get(
        "nodes",
        [],
    ):
        link = node["link"]

        item = dict(
            metadata.get(
                link,
                {},
            )
        )

        exit_ip = (
            item.get(
                "exit_ip",
                "",
            )
            or ""
        )

        trace_country = (
            item.get(
                "trace_country",
                "",
            )
            .strip()
            .upper()
        )

        db_item = city_lookup.get(
            exit_ip,
            {},
        )

        db_country = (
            db_item.get(
                "db_country",
                "",
            )
            .strip()
            .upper()
        )

        # Cloudflare trace is preferred because it is observed
        # through the actual VPN connection. DB-IP of that same
        # observed exit IP is the fallback.
        if (
            re.fullmatch(
                r"[A-Z]{2}",
                trace_country,
            )
            and trace_country
            not in {"XX", "ZZ"}
        ):
            exit_country = trace_country
            country_source = (
                "cloudflare-trace"
            )

        elif (
            re.fullmatch(
                r"[A-Z]{2}",
                db_country,
            )
            and db_country
            not in {"XX", "ZZ"}
        ):
            exit_country = db_country
            country_source = (
                "dbip-exit-ip"
            )

        else:
            exit_country = ""
            country_source = ""

        city = db_item.get(
            "city",
            "",
        )

        # Never combine a city from a DB country that disagrees
        # with the authoritative actual-exit country.
        if (
            city
            and exit_country
            and db_country
            and db_country != exit_country
        ):
            city = ""

        node["source_country"] = node.get(
            "country",
            "XX",
        )

        node["exit_ip"] = (
            exit_ip or None
        )

        node["exit_country"] = (
            exit_country or None
        )

        node["exit_country_source"] = (
            country_source or None
        )

        node["exit_city"] = (
            city or None
        )

        node["exit_region"] = (
            db_item.get("region")
            or None
        )

        node["exit_db_country"] = (
            db_country or None
        )

        node["exit_geo_status"] = (
            item.get(
                "exit_geo_status",
                "not-probed",
            )
        )

        if item.get(
            "exit_geo_error"
        ):
            node["exit_geo_error"] = (
                item["exit_geo_error"]
            )

        if item.get(
            "exit_geo_attempts"
        ):
            node["exit_geo_attempts"] = (
                item["exit_geo_attempts"]
            )

        if exit_country:
            exit_country_counts[
                exit_country
            ] += 1

        # Absolute country gate.
        if not exit_country:
            node["country_gate"] = (
                "rejected-unknown-actual-exit"
            )
            unknown += 1
            continue

        if (
            exit_country
            not in ALLOWED_ACTUAL_EXIT_COUNTRIES
        ):
            node["country_gate"] = (
                "rejected-disallowed-actual-exit"
            )
            rejected_country_counts[
                exit_country
            ] += 1
            rejected_country += 1
            continue

        node["country_gate"] = "passed"

        if city:
            complete += 1
        else:
            country_only += 1

        allowed_nodes.append(node)

    # Keep only nodes whose ACTUAL VPN exit passed the absolute
    # country gate. Re-rank after filtering so labels are
    # contiguous in the published subscription.
    for index, node in enumerate(
        allowed_nodes,
        1,
    ):
        node["rank"] = index

    status["nodes"] = allowed_nodes

    status["exit_geography"] = {
        "mode":
            "actual-vpn-exit-strict-country-gate",
        "affects_qualification":
            True,
        "allowed_countries":
            sorted(
                ALLOWED_ACTUAL_EXIT_COUNTRIES
            ),
        "trace_url":
            EXIT_TRACE_URL,
        "ipv4_database":
            str(CITY_DB_IPV4),
        "ipv6_database":
            str(CITY_DB_IPV6),
        "observed_countries":
            dict(exit_country_counts),
        "accepted_countries":
            dict(
                Counter(
                    node["exit_country"]
                    for node in allowed_nodes
                )
            ),
        "rejected_countries":
            dict(rejected_country_counts),
        "complete":
            complete,
        "country_only":
            country_only,
        "unknown_rejected":
            unknown,
        "disallowed_country_rejected":
            rejected_country,
        "country_qualified":
            len(allowed_nodes),
    }


def valid_node_evidence(node: dict, rounds: int) -> bool:
    if rounds not in (3, 4, 5):
        return False
    services = node.get("services", {})
    if any(services.get(name, {}).get("passed") != rounds or services.get(name, {}).get("attempts") != rounds
           for name in ("chatgpt", "youtube", "instagram")):
        return False
    samples = node.get("latency_samples_ms", [])
    if len(samples) != rounds or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in samples):
        return False
    median = node.get("median_latency")
    return (not isinstance(median, bool) and isinstance(median, (int, float))
            and 0 <= median < MAX_LOCAL_MEDIAN_LATENCY_MS
            and math.isclose(median, statistics.median(samples), abs_tol=0.001))


def finalize_local_selection(
    qualified: list[str],
    status: dict,
) -> list[str]:
    allowed_nodes = status.get(
        "nodes",
        [],
    )

    allowed_links = {
        node["link"]
        for node in allowed_nodes
    }

    # Preserve the strict local stability/latency ordering
    # established by run_local_probe(), but fail closed on
    # excessive or missing local latency before applying the
    # publication cap.
    latency_qualified_links = {
        node["link"]
        for node in allowed_nodes
        if (
            isinstance(
                node.get("median_latency"),
                (int, float),
            )
            and not isinstance(node.get("median_latency"), bool)
            and 0 <= node["median_latency"] < MAX_LOCAL_MEDIAN_LATENCY_MS
        )
    }

    country_qualified = [
        link
        for link in qualified
        if link in allowed_links
    ]

    latency_qualified = [
        link
        for link in country_qualified
        if link in latency_qualified_links
        and valid_node_evidence(next(node for node in allowed_nodes if node["link"] == link), status.get("stability", {}).get("rounds", 0))
    ]

    selected = latency_qualified[
        :MAX_LOCAL_PUBLISHED_NODES
    ]

    selected_set = set(selected)

    selected_nodes = [
        node
        for node in status.get(
            "nodes",
            [],
        )
        if node["link"] in selected_set
    ]

    node_by_link = {
        node["link"]: node
        for node in selected_nodes
    }

    selected_nodes = [
        node_by_link[link]
        for link in selected
    ]

    for index, node in enumerate(
        selected_nodes,
        1,
    ):
        node["rank"] = index

    status["nodes"] = selected_nodes

    status["stability"][
        "pre_country_qualified"
    ] = status["stability"].get(
        "qualified",
        len(qualified),
    )

    status["stability"][
        "country_qualified"
    ] = len(country_qualified)

    status["stability"][
        "qualified"
    ] = len(selected)

    status["selection"] = {
        "policy":
            "strict-actual-exit-and-local-stability",
        "allowed_actual_exit_countries":
            sorted(
                ALLOWED_ACTUAL_EXIT_COUNTRIES
            ),
        "maximum_published_nodes":
            MAX_LOCAL_PUBLISHED_NODES,
        "maximum_median_latency_ms":
            MAX_LOCAL_MEDIAN_LATENCY_MS,
        "country_qualified":
            len(country_qualified),
        "latency_qualified":
            len(latency_qualified),
        "published":
            len(selected),
        "padding":
            False,
    }

    status["countries"] = dict(
        Counter(
            node["exit_country"]
            for node in selected_nodes
        )
    )

    return selected


def _active_ipv4_tunnel_routes() -> list[str]:
    """
    Return active IPv4 routes carried by utun interfaces.

    Happ/sing-box on macOS may implement a full tunnel using
    split-default routes (for example 1/8 ... 128.0/1) while the
    traditional 0/0 default route remains on en0. Therefore
    `route get default` alone is not a valid VPN detector.
    """
    try:
        result = subprocess.run(
            [
                "netstat",
                "-rn",
                "-f",
                "inet",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return []

    if result.returncode != 0:
        return []

    routes: list[str] = []

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) < 4:
            continue

        interface = fields[-1]

        if not interface.startswith("utun"):
            continue

        destination = fields[0]

        routes.append(
            f"{destination}@{interface}"
        )

    return routes


def ensure_probe_network(
    forced_interface: str,
) -> None:
    system_interface = route_interface()

    print(
        "System default route interface:",
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

    forced_ipv4 = ipv4_match.group(1)

    print(
        "Probe interface IPv4:",
        forced_ipv4,
    )

    tunnel_routes = (
        _active_ipv4_tunnel_routes()
    )

    if tunnel_routes:
        print(
            "Active IPv4 tunnel routing detected: "
            + ", ".join(tunnel_routes[:12])
            + (
                " ..."
                if len(tunnel_routes) > 12
                else ""
            )
        )
    elif (
        system_interface
        and system_interface.startswith("utun")
    ):
        print(
            "Active system VPN detected via "
            "default route."
        )
    else:
        print(
            "No IPv4 utun routing detected."
        )

    print(
        "Probe VLESS transport sockets are forced "
        f"through physical interface {forced_interface}; "
        "the active Happ tunnel is bypassed for the "
        "underlying test connection."
    )


def load_service_probe():
    spec = importlib.util.spec_from_file_location("bestlocal_service_probe", ROOT / "scripts" / "service_probe.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def require_fresh_timestamp(value: str | None, max_hours: float, description: str) -> None:
    try:
        stamp = datetime.fromisoformat(str(value).replace(" UTC", "+00:00").replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("missing timezone")
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
    except (ValueError, TypeError):
        raise RuntimeError(f"Missing or invalid {description} timestamp") from None
    if age < -300 or age > max_hours * 3600:
        raise RuntimeError(f"Stale or future {description}; maximum age {max_hours:g}h")


async def run_local_probe(build, links, final_rounds, minimum_successes, input_description):
    if not 3 <= final_rounds <= 5 or minimum_successes != final_rounds:
        raise RuntimeError("Local validation requires 3..5 rounds and every round must succeed")
    service_probe = load_service_probe()
    reports = await service_probe.validate_candidates(
        build, links, rounds=final_rounds,
        interface=build.CFG.get("_probe_default_interface", "en0"),
    )
    build._local_reports = reports
    history_path = STATE_DIR / "local-reliability.json"
    try:
        history = json.loads(history_path.read_text())
    except (OSError, ValueError):
        history = {}
    now = int(time.time())
    history = {k: v for k, v in history.items() if isinstance(v, dict) and now - v.get("last_seen", 0) < 28 * 86400}
    gate_counts = {name: 0 for name in ("chatgpt", "youtube", "instagram")}
    qualified = []
    diagnostics = []
    for rank, link in enumerate(links, 1):
        result = reports.get(link, {})
        services = result.get("services", {})
        key = hashlib.sha256(link.split("#", 1)[0].encode()).hexdigest()
        sample = history.setdefault(key, {"runs": 0, "passes": 0})
        sample["runs"] = min(sample.get("runs", 0), 99) + 1
        passed = bool(result.get("qualified")) and all(
            services.get(name, {}).get("passed") == final_rounds
            and services.get(name, {}).get("attempts") == final_rounds
            for name in gate_counts
        )
        latency = result.get("median_ms")
        measurements = result.get("latency_samples_ms", [])
        passed = passed and len(measurements) == final_rounds and isinstance(latency, (int, float)) and not isinstance(latency, bool) and 0 <= latency < MAX_LOCAL_MEDIAN_LATENCY_MS
        sample["passes"] = min(sample.get("passes", 0), sample["runs"] - 1) + int(passed)
        sample["last_seen"] = now
        reliability = (sample["passes"] + 1) / (sample["runs"] + 2)
        for name in gate_counts:
            gate_counts[name] += int(services.get(name, {}).get("passed") == final_rounds)
        if passed:
            qualified.append((link, result, rank, reliability))
        diagnostic = {"id": key[:12], "upstream_rank": rank, "qualified": passed,
                      "services": services, "latency_samples_ms": measurements,
                      "median_latency": latency if isinstance(latency, (float, int)) and math.isfinite(latency) else None,
                      "rejection_reasons": result.get("rejection_reasons", ["missing-result"] if not result else [])}
        diagnostics.append(diagnostic)
        print("Candidate", diagnostic["id"], json.dumps({k: v for k, v in diagnostic.items() if k not in {"id", "upstream_rank"}}, allow_nan=False), flush=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    # Hash-only history is diagnostic; no candidate credentials are stored here.
    write_status(history_path, dict(sorted(history.items(), key=lambda item: item[1]["last_seen"], reverse=True)[:5000]))
    qualified.sort(key=lambda item: (-item[3], item[1]["median_ms"], item[1]["p95_ms"], item[2]))
    status = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "bestlocal-strict-services-v6",
        "input": {"path": input_description, "nodes": len(links)},
        "network": {"system_route_interface": route_interface(), "probe_default_interface": build.CFG.get("_probe_default_interface", "en0"), "system_network_modified": False},
        "gates": {"preliminary": {}, "mandatory": gate_counts},
        "latency_method": "median of 3..5 fresh HTTPS gstatic generate_204 completion times in milliseconds via the candidate authenticated SOCKS/VLESS path; includes SOCKS, transport and TLS; strictly below 500ms",
        "stability": {"rounds": final_rounds, "minimum_successes": minimum_successes,
                      "first_pass_survivors": len(qualified), "round_survivors": [len(qualified)] * final_rounds, "qualified": len(qualified)},
        "countries": {}, "diagnostics": diagnostics,
        "nodes": [{"rank": index, "country": country_from_link(link), "link": link,
                   "successful_final_rounds": final_rounds, "latency_samples": len(result["latency_samples_ms"]),
                   "latency_samples_ms": result["latency_samples_ms"],
                   "median_latency": result["median_ms"], "p95_latency": result["p95_ms"],
                   "services": result["services"], "historical_reliability": reliability,
                   "validated_at": result["validated_at"], "upstream_rank": upstream_rank}
                  for index, (link, result, upstream_rank, reliability) in enumerate(qualified, 1)],
    }
    return [item[0] for item in qualified], status


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
        "# v6.0 — LOCAL NETWORK VERIFIED PROXIES",
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
            "ChatGPT providers JSON + YouTube video metadata + "
            "Instagram application HTML; median proxy HTTPS latency <500 ms"
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
            "# Generated from Best50 "
            "and re-tested through the current "
            "local network."
        ),
        "#",
    ]

    nodes = status.get(
        "nodes",
        [],
    )

    if len(nodes) != len(links):
        raise RuntimeError(
            "Status node count does not match "
            "qualified link count"
        )

    published_links = [
        published_link(
            node["link"],
            int(node["rank"]),
            node.get("exit_country"),
            node.get("exit_city"),
        )
        for node in nodes
    ]

    lines.extend(
        published_links
    )

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
            allow_nan=False,
        )
        + "\n"
    )

    temp.replace(path)


def git_output(
    *args: str,
    cwd: Path | None = None,
) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT if cwd is None else cwd,
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
        if line.strip() and not line.lstrip().startswith("#")
    ]

    status = json.loads(
        status_path.read_text()
    )

    qualified = int(
        status["stability"]["qualified"]
    )

    expected_published_links = [
        published_link(
            node["link"],
            int(node["rank"]),
            node.get("exit_country"),
            node.get("exit_city"),
        )
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

    if links != expected_published_links:
        raise RuntimeError(
            "Published subscription order/names do not match "
            "local ranking in status"
        )

    if len(links) > MAX_LOCAL_PUBLISHED_NODES:
        raise RuntimeError("Regional result exceeds publication cap")
    if status.get("algorithm") != "bestlocal-strict-services-v6":
        raise RuntimeError("Missing strict service validation policy")
    require_fresh_timestamp(status.get("generated_at"), 6, "local validation")
    require_fresh_timestamp(status.get("upstream_generated_at"), 18, "Best50 input")
    rounds = status.get("stability", {}).get("rounds", 0)
    if rounds not in (3, 4, 5) or status["stability"].get("minimum_successes") != rounds:
        raise RuntimeError("Incomplete validation rounds")
    for node in status["nodes"]:
        require_fresh_timestamp(node.get("validated_at"), 6, "candidate validation")
        if not valid_node_evidence(node, rounds):
            raise RuntimeError("A node lacks required service or latency evidence")
        if node.get("exit_country") not in ALLOWED_ACTUAL_EXIT_COUNTRIES:
            raise RuntimeError("A node lacks an allowed actual exit country")

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
            "output/best50.txt changed "
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


def _publish_regional_once(
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

    build = load_build_module()
    tested = read_links_text(run_git("show", f"{tested_sha}:{DEFAULT_UPSTREAM_PATH}"), "tested Best50")
    allowed = {build.normalized_fingerprint(build.parse_vless(link)) for link in tested}
    status = json.loads(status_path.read_text())
    if any(build.normalized_fingerprint(build.parse_vless(node["link"])) not in allowed for node in status["nodes"]):
        raise RuntimeError("Refusing publication of a node absent from tested Best50")

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

    if regional_exists:
        try:
            previous_status = json.loads(git_output("show", f"{base_ref}:{REGIONAL_STATUS_PATH}"))
            previous_time = datetime.fromisoformat(previous_status["generated_at"].replace("Z", "+00:00"))
            current_time = datetime.fromisoformat(status["generated_at"].replace("Z", "+00:00"))
        except (RuntimeError, KeyError, TypeError, ValueError):
            previous_time = current_time = None
        if previous_time is not None and current_time is not None and previous_time > current_time:
            raise RuntimeError("A newer regional validation already exists; refusing older result")

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


def publish_regional_result(subscription_path: Path, status_path: Path, tested_sha: str) -> None:
    for attempt in range(3):
        try:
            _publish_regional_once(subscription_path, status_path, tested_sha)
            return
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            if attempt == 2:
                raise
            print(f"Publication attempt {attempt + 1} failed ({type(exc).__name__}); retrying safely", flush=True)
            time.sleep(2 ** (attempt + 1))


def publish_regional_health(status: dict) -> None:
    """Publish latest-attempt diagnostics without replacing the retained subscription."""
    health = {
        "schema": 1, "policy": "bestlocal-strict-services-v6",
        "latest_attempt_at": status["generated_at"],
        "input": status.get("input"), "upstream_sha": status.get("upstream_sha"),
        "upstream_generated_at": status.get("upstream_generated_at"),
        "qualified": status["stability"]["qualified"],
        "artifact_status": "freshly-validated" if status["stability"]["qualified"] else "last-known-good-retained; latest strict validation found no qualifiers",
        "current_policy_validated": bool(status["stability"]["qualified"]),
        "gates": status.get("gates"), "latency_method": status.get("latency_method"),
        "diagnostics": status.get("diagnostics", []),
    }
    for attempt in range(3):
        try:
            git_output("fetch", REGIONAL_REMOTE, REGIONAL_BRANCH)
            with tempfile.TemporaryDirectory(prefix="bestlocal-health-") as directory:
                worktree = Path(directory) / "checkout"
                try:
                    git_output("worktree", "add", "--detach", str(worktree), f"{REGIONAL_REMOTE}/{REGIONAL_BRANCH}")
                    target = worktree / "output/local-health.json"
                    if target.is_file():
                        previous = json.loads(target.read_text())
                        previous_stamp = datetime.fromisoformat(previous["latest_attempt_at"].replace("Z", "+00:00"))
                        if previous_stamp > datetime.fromisoformat(health["latest_attempt_at"].replace("Z", "+00:00")):
                            print("A newer regional health report exists; retaining it")
                            return
                    write_status(target, health)
                    git_output("add", "-f", "output/local-health.json", cwd=worktree)
                    diff = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=worktree, timeout=30)
                    if diff.returncode == 0:
                        return
                    if diff.returncode != 1:
                        raise RuntimeError("Cannot inspect regional health diff")
                    git_output("commit", "-m", "chore: record regional validation health", cwd=worktree)
                    git_output("push", REGIONAL_REMOTE, f"HEAD:refs/heads/{REGIONAL_BRANCH}", cwd=worktree)
                    print("Regional health published; subscription retained" if not health["qualified"] else "Regional health published", flush=True)
                    return
                finally:
                    subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=ROOT, capture_output=True, timeout=30)
        except (RuntimeError, subprocess.TimeoutExpired):
            if attempt == 2:
                raise
            time.sleep(2 ** (attempt + 1))


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
            "origin/main:output/best50.txt."
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
        default=5,
        help=(
            "Number of local final stability rounds "
            "(default: 5)"
        ),
    )

    parser.add_argument(
        "--minimum-successes",
        type=int,
        default=5,
        help=(
            "Required complete final rounds "
            "(default: 5)"
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
            "origin/main Best50"
        )

    if not 3 <= args.rounds <= 5 or args.minimum_successes != args.rounds:
        raise RuntimeError("Require 3..5 rounds and --minimum-successes equal to --rounds")
    if args.interface != "en0":
        raise RuntimeError("Authoritative local validation must use en0")

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
        input_mode = "origin-main-best50"

    if upstream_sha:
        require_fresh_timestamp(upstream_generated, 18, "Best50 input")
    if len(links) > 50:
        raise RuntimeError("Best50 input contains more than 50 candidates")
    print(f"Input nodes: {len(links)}")
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

    print()
    print(
        "========================================"
    )
    print(
        "ACTUAL VPN EXIT GEO ENRICHMENT"
    )
    print(
        "========================================"
    )

    print(
        "Actual VPN exit geography is an authoritative "
        "final country gate."
    )

    print(
        "Allowed actual exit countries: "
        + ", ".join(
            sorted(
                ALLOWED_ACTUAL_EXIT_COUNTRIES
            )
        )
    )

    # Use the trace captured by the very same isolated candidate process.
    # Do not start the legacy fixed-port enrichment engine.
    exit_metadata = {}
    for link in qualified:
        trace = build._local_reports.get(link, {}).get("exit_trace", {})
        if isinstance(trace, dict) and trace.get("ip"):
            parsed = _parse_cloudflare_trace(f"ip={trace['ip']}\nloc={trace.get('loc', '')}\n".encode())
            if parsed:
                exit_metadata[link] = {**parsed, "exit_geo_status": "trace-ok"}

    apply_exit_geography(
        status,
        exit_metadata,
    )

    qualified = finalize_local_selection(
        qualified,
        status,
    )

    geo_summary = status[
        "exit_geography"
    ]

    print(
        "Exit geo complete:     "
        f"{geo_summary['complete']}"
    )

    print(
        "Exit country only:     "
        f"{geo_summary['country_only']}"
    )

    print(
        "Unknown rejected:      "
        f"{geo_summary['unknown_rejected']}"
    )

    print(
        "Disallowed rejected:   "
        f"{geo_summary['disallowed_country_rejected']}"
    )

    print(
        "Observed exit countries: "
        f"{geo_summary['observed_countries']}"
    )

    print(
        "Accepted exit countries: "
        f"{geo_summary['accepted_countries']}"
    )

    print(
        "Final published nodes: "
        f"{len(qualified)}"
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

    if qualified:
        write_subscription(args.output, qualified, status)
    else:
        status["publication"].update({"status": "withheld-empty", "last_known_good_preserved": True})

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
        "Actual countries:    "
        + ", ".join(
            f"{country}={count}"
            for country, count
            in sorted(
                status["exit_geography"]["accepted_countries"].items()
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
        print("WARNING: no locally qualified nodes; retained subscription is not a fresh validation.")
        if args.publish:
            try:
                publish_regional_health(status)
            except (RuntimeError, subprocess.TimeoutExpired):
                print("WARNING: health publication failed; scheduler will retry; subscription remains unchanged", flush=True)
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

        publish_regional_result(args.output, args.status, upstream_sha)
        publish_regional_health(status)

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
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with (STATE_DIR / "local-probe.lock").open("a+") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another BestLocal probe holds the validation lock") from None
            return asyncio.run(async_main())
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
