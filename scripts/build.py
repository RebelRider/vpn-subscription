#!/usr/bin/env python3

"""
Best50 v2 — quality-first VLESS subscription builder.

Pipeline:

1. Fetch upstream VLESS subscriptions.
2. Parse and deduplicate candidates.
3. First-pass REAL HTTP connectivity test through sing-box.
4. Keep the best first-pass candidates.
5. Re-test finalists multiple times.
6. Combine current results with historical stability.
7. Publish best20 / best50 / best100.
8. Save detailed status and rolling history.

Important:
The latency measured here is the end-to-end HTTP request time from the
GitHub Actions runner through the candidate proxy to the test URL.
It is NOT the same thing as RTT from the end user's country/network.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
CFG = json.loads((ROOT / "config.json").read_text())

OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

SING_BOX = "sing-box"

# ---------------------------------------------------------
# Utility
# ---------------------------------------------------------


def fetch(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Best50Builder/2.0",
            "Accept": "*/*",
        },
    )

    with urllib.request.urlopen(req, timeout=25) as response:
        raw = response.read()

    text = raw.decode("utf-8", "ignore").strip()

    # Some subscriptions are base64 encoded.
    compact = re.sub(r"\s+", "", text)

    if "vless://" not in text.lower():
        try:
            decoded = base64.b64decode(compact + "===")
            candidate = decoded.decode("utf-8", "ignore")

            if "vless://" in candidate.lower():
                text = candidate
        except Exception:
            pass

    return text


def extract_vless(text: str) -> list[str]:
    found: list[str] = []

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        match = re.search(r"vless://\S+", line, re.I)

        if match:
            link = match.group(0).rstrip("`),]")

            if link.lower().startswith("vless://"):
                found.append(link)

    return found


def fingerprint(link: str) -> str:
    return hashlib.sha256(link.encode()).hexdigest()


def q1(
    query: dict[str, list[str]],
    key: str,
    default: str = "",
) -> str:
    return query.get(key, [default])[0]


# ---------------------------------------------------------
# VLESS -> sing-box
# ---------------------------------------------------------


def vless_to_singbox(
    link: str,
    tag: str = "node",
) -> dict:
    uri = urlsplit(link)

    if uri.scheme.lower() != "vless":
        raise ValueError("not VLESS")

    if not uri.hostname:
        raise ValueError("missing host")

    if not uri.port:
        raise ValueError("missing port")

    if not uri.username:
        raise ValueError("missing UUID")

    query = parse_qs(
        uri.query,
        keep_blank_values=True,
    )

    network = q1(
        query,
        "type",
        "tcp",
    ).lower()

    security = q1(
        query,
        "security",
        "",
    ).lower()

    flow = q1(
        query,
        "flow",
        "",
    )

    # Deliberately unsupported in this version.
    unsupported = {
        "xhttp",
        "splithttp",
        "quic",
        "kcp",
    }

    if network in unsupported:
        raise ValueError(
            f"unsupported transport: {network}"
        )

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": uri.hostname,
        "server_port": uri.port,
        "uuid": unquote(uri.username),
    }

    if flow:
        outbound["flow"] = flow

    # TLS / Reality
    if security in ("tls", "reality"):
        tls = {
            "enabled": True,
            "server_name": (
                q1(query, "sni")
                or q1(query, "host")
                or uri.hostname
            ),
        }

        fingerprint_value = q1(
            query,
            "fp",
        )

        if fingerprint_value:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fingerprint_value,
            }

        alpn = q1(
            query,
            "alpn",
        )

        if alpn:
            tls["alpn"] = [
                value
                for value in alpn.split(",")
                if value
            ]

        if security == "reality":
            public_key = (
                q1(query, "pbk")
                or q1(query, "publicKey")
            )

            short_id = (
                q1(query, "sid")
                or q1(query, "shortId")
            )

            if not public_key:
                raise ValueError(
                    "Reality without public key"
                )

            if not short_id:
                raise ValueError(
                    "Reality without short id"
                )

            tls["reality"] = {
                "enabled": True,
                "public_key": public_key,
                "short_id": short_id,
            }

        outbound["tls"] = tls

    elif security in ("", "none"):
        pass

    else:
        raise ValueError(
            f"unsupported security: {security}"
        )

    # WebSocket
    if network == "ws":
        path = unquote(
            q1(query, "path", "/")
        )

        host = q1(
            query,
            "host",
        )

        headers = {}

        if host:
            headers["Host"] = host

        outbound["transport"] = {
            "type": "ws",
            "path": path,
            "headers": headers,
        }

    # gRPC
    elif network == "grpc":
        service_name = unquote(
            q1(query, "serviceName", "")
        )

        if not service_name:
            raise ValueError(
                "gRPC without serviceName"
            )

        outbound["transport"] = {
            "type": "grpc",
            "service_name": service_name,
        }

    # HTTP transport
    elif network == "http":
        path = unquote(
            q1(query, "path", "/")
        )

        host = q1(
            query,
            "host",
        )

        outbound["transport"] = {
            "type": "http",
            "path": path,
            "host": [host] if host else [],
        }

    # HTTPUpgrade
    elif network == "httpupgrade":
        path = unquote(
            q1(query, "path", "/")
        )

        host = q1(
            query,
            "host",
        )

        headers = {}

        if host:
            headers["Host"] = host

        outbound["transport"] = {
            "type": "httpupgrade",
            "path": path,
            "headers": headers,
        }

    # TCP
    elif network == "tcp":
        header_type = q1(
            query,
            "headerType",
            "",
        ).lower()

        if header_type == "http":
            host = q1(
                query,
                "host",
            )

            path = unquote(
                q1(query, "path", "/")
            )

            outbound["transport"] = {
                "type": "http",
                "host": [host] if host else [],
                "path": path,
            }

        elif header_type not in ("", "none"):
            raise ValueError(
                f"unsupported TCP headerType: {header_type}"
            )

    return outbound


# ---------------------------------------------------------
# Process execution
# ---------------------------------------------------------


async def run_process(
    command: list[str],
    timeout: float,
) -> tuple[int, bytes, bytes]:

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )

        return (
            process.returncode,
            stdout,
            stderr,
        )

    except asyncio.TimeoutError:
        process.kill()

        try:
            await process.wait()
        except Exception:
            pass

        return (
            124,
            b"",
            b"timeout",
        )


# ---------------------------------------------------------
# Single real connectivity probe
# ---------------------------------------------------------


async def probe_one(
    link: str,
    sem: asyncio.Semaphore,
    index: int,
) -> tuple[str, float | None]:

    async with sem:

        try:
            outbound = vless_to_singbox(link)

        except Exception as error:
            print(
                f"SKIP parse: {error}",
                file=sys.stderr,
            )

            return link, None

        # Keep ports deterministic and unique.
        port = 22000 + (index % 20000)

        with tempfile.TemporaryDirectory() as temp_dir:

            config_path = (
                Path(temp_dir)
                / "config.json"
            )

            config = {
                "log": {
                    "level": "error"
                },

                "dns": {
                    "servers": [
                        {
                            "type": "local",
                            "tag": "local",
                        }
                    ],
                    "final": "local",
                },

                "inbounds": [
                    {
                        "type": "socks",
                        "tag": "socks",
                        "listen": "127.0.0.1",
                        "listen_port": port,
                    }
                ],

                "outbounds": [
                    outbound,

                    {
                        "type": "direct",
                        "tag": "direct",
                    },
                ],

                "route": {
                    "final": "node",
                },
            }

            config_path.write_text(
                json.dumps(
                    config,
                    ensure_ascii=False,
                )
            )

            # Validate config first.
            check_code, _, check_error = (
                await run_process(
                    [
                        SING_BOX,
                        "check",
                        "-c",
                        str(config_path),
                    ],
                    8,
                )
            )

            if check_code != 0:
                return link, None

            # Start proxy.
            process = (
                await asyncio.create_subprocess_exec(
                    SING_BOX,
                    "run",
                    "-c",
                    str(config_path),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            )

            try:
                # Give sing-box time to initialize.
                await asyncio.sleep(0.30)

                start = time.perf_counter()

                code, output, _ = (
                    await run_process(
                        [
                            "curl",

                            "--socks5-hostname",
                            f"127.0.0.1:{port}",

                            "--connect-timeout",
                            str(
                                CFG[
                                    "connect_timeout"
                                ]
                            ),

                            "--max-time",
                            str(
                                CFG[
                                    "request_timeout"
                                ]
                            ),

                            "-sS",

                            "-o",
                            "/dev/null",

                            "-w",
                            "%{http_code}",

                            CFG["test_url"],
                        ],

                        CFG["request_timeout"] + 3,
                    )
                )

                elapsed = (
                    time.perf_counter()
                    - start
                ) * 1000

                http_code = (
                    output
                    .decode(
                        errors="ignore"
                    )
                    .strip()
                )

                if (
                    code == 0
                    and http_code.startswith(
                        ("2", "3")
                    )
                ):
                    return (
                        link,
                        elapsed,
                    )

                return link, None

            finally:
                process.terminate()

                try:
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=2,
                    )

                except asyncio.TimeoutError:
                    process.kill()

                    try:
                        await process.wait()
                    except Exception:
                        pass


# ---------------------------------------------------------
# History
# ---------------------------------------------------------


def load_history() -> dict:

    path = (
        ROOT
        / CFG["history_file"]
    )

    if not path.exists():
        return {}

    try:
        return json.loads(
            path.read_text()
        )

    except Exception:
        return {}


def save_history(
    history: dict,
) -> None:

    path = (
        ROOT
        / CFG["history_file"]
    )

    path.write_text(
        json.dumps(
            history,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


def update_history(
    history: dict,
    link: str,
    latency: float | None,
    now: int,
) -> dict:

    fp = fingerprint(link)

    item = history.get(
        fp,
        {
            "successes": 0,
            "failures": 0,
            "last_success": 0,
            "last_failure": 0,
            "best_ms": None,
            "latencies": [],
        },
    )

    if latency is not None:

        item["successes"] += 1
        item["last_success"] = now

        if item["best_ms"] is None:
            item["best_ms"] = latency
        else:
            item["best_ms"] = min(
                item["best_ms"],
                latency,
            )

        latencies = item.get(
            "latencies",
            [],
        )

        latencies.append(
            round(latency, 1)
        )

        # Keep rolling history small.
        item["latencies"] = latencies[-20:]

    else:

        item["failures"] += 1
        item["last_failure"] = now

    # Protect the history from unbounded growth.
    item["successes"] = int(
        item.get("successes", 0)
    )

    item["failures"] = int(
        item.get("failures", 0)
    )

    return item


# ---------------------------------------------------------
# Scoring
# ---------------------------------------------------------


def calculate_score(
    latency: float,
    item: dict,
    current_successes: int,
    current_attempts: int,
    now: int,
) -> float:

    total_successes = (
        int(item.get("successes", 0))
    )

    total_failures = (
        int(item.get("failures", 0))
    )

    historical_attempts = (
        total_successes
        + total_failures
    )

    historical_success_rate = (
        total_successes
        / historical_attempts
        if historical_attempts
        else 0.0
    )

    current_success_rate = (
        current_successes
        / current_attempts
        if current_attempts
        else 0.0
    )

    # Blend current and historical reliability.
    reliability = (
        current_success_rate * 0.65
        + historical_success_rate * 0.35
    )

    # Latency component.
    #
    # 50ms -> very good
    # 500ms -> acceptable
    # 1000ms -> poor
    latency_score = max(
        0.0,
        1.0 - latency / 1000.0,
    )

    # Consistency of recent measurements.
    latencies = item.get(
        "latencies",
        [],
    )

    consistency = 0.0

    if len(latencies) >= 2:
        average = (
            sum(latencies)
            / len(latencies)
        )

        if average > 0:
            deviation = (
                max(latencies)
                - min(latencies)
            ) / average

            consistency = max(
                0.0,
                1.0 - min(
                    deviation,
                    1.0,
                ),
            )

    # Recency bonus.
    last_success = int(
        item.get(
            "last_success",
            0,
        )
    )

    age_hours = (
        max(
            0,
            now - last_success,
        )
        / 3600
        if last_success
        else 999
    )

    recency = max(
        0.0,
        1.0 - age_hours / 24.0,
    )

    # Final normalized score.
    #
    # Reliability: 40%
    # Latency:     35%
    # Consistency: 15%
    # Recency:     10%
    score = (
        reliability * 0.40
        + latency_score * 0.35
        + consistency * 0.15
        + recency * 0.10
    )

    return score


# ---------------------------------------------------------
# First pass
# ---------------------------------------------------------


async def run_first_pass(
    links: list[str],
) -> list[tuple[str, float]]:

    sem = asyncio.Semaphore(
        CFG["max_parallel"]
    )

    results = await asyncio.gather(
        *(
            probe_one(
                link,
                sem,
                index,
            )

            for index, link
            in enumerate(links)
        )
    )

    return [
        (link, latency)
        for link, latency
        in results
        if latency is not None
    ]


# ---------------------------------------------------------
# Final repeated verification
# ---------------------------------------------------------


async def run_final_pass(
    links: list[str],
) -> dict[str, list[float]]:

    sem = asyncio.Semaphore(
        CFG["max_parallel_final"]
    )

    final: dict[
        str,
        list[float]
    ] = {
        link: []
        for link in links
    }

    attempts = CFG[
        "final_test_attempts"
    ]

    for round_number in range(
        attempts
    ):

        print(
            "Final verification "
            f"{round_number + 1}/{attempts}"
        )

        results = await asyncio.gather(
            *(
                probe_one(
                    link,
                    sem,
                    index,
                )

                for index, link
                in enumerate(links)
            )
        )

        for link, latency in results:

            if latency is not None:
                final[link].append(
                    latency
                )

    return final


# ---------------------------------------------------------
# Publishing
# ---------------------------------------------------------


def publish_file(
    name: str,
    chosen: list[dict],
    now: int,
    candidates: int,
    first_pass_working: int,
    final_tested: int,
) -> None:

    lines = [
        "# Best50 v2 — REAL-HTTP-TESTED VLESS",
        (
            "# generated: "
            + time.strftime(
                "%Y-%m-%d %H:%M:%S UTC",
                time.gmtime(now),
            )
        ),
        f"# candidates: {candidates}",
        f"# first_pass_working: {first_pass_working}",
        f"# final_tested: {final_tested}",
        f"# published: {len(chosen)}",
        f"# test_url: {CFG['test_url']}",
        "#",
        "# Quality-filtered public VLESS configurations.",
        "#",
    ]

    lines.extend(
        item["link"]
        for item in chosen
    )

    (
        OUT / name
    ).write_text(
        "\n".join(lines)
        + "\n"
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------


async def main_async():

    now = int(
        time.time()
    )

    all_links: list[str] = []

    # -----------------------------
    # Fetch
    # -----------------------------

    for source in CFG["sources"]:

        try:

            text = await asyncio.to_thread(
                fetch,
                source["url"],
            )

            links = extract_vless(
                text
            )

            print(
                f"{source['name']}: "
                f"{len(links)} VLESS candidates"
            )

            all_links.extend(
                links
            )

        except Exception as error:

            print(
                f"WARNING "
                f"{source['name']}: "
                f"{error}",
                file=sys.stderr,
            )

    # -----------------------------
    # Deduplicate
    # -----------------------------

    unique: dict[
        str,
        str
    ] = {}

    for link in all_links:

        unique.setdefault(
            fingerprint(link),
            link,
        )

    # Important:
    # Don't arbitrarily take the first 100.
    # Use the configured larger candidate pool.
    candidate_limit = int(
        CFG["candidate_limit"]
    )

    links = list(
        unique.values()
    )[:candidate_limit]

    print(
        f"Unique candidates: "
        f"{len(unique)}"
    )

    print(
        f"Candidates selected: "
        f"{len(links)}"
    )

    # -----------------------------
    # First pass
    # -----------------------------

    first_pass = (
        await run_first_pass(
            links
        )
    )

    print(
        "First-pass working: "
        f"{len(first_pass)}"
    )

    if not first_pass:

        print(
            "ERROR: no working nodes "
            "found; preserving previous "
            "published files."
        )

        return 1

    # -----------------------------
    # Update history with first pass
    # -----------------------------

    history = load_history()

    for link, latency in first_pass:

        history[
            fingerprint(link)
        ] = update_history(
            history,
            link,
            latency,
            now,
        )

    # Failures from first pass.
    first_pass_set = {
        fingerprint(link)
        for link, _
        in first_pass
    }

    for link in links:

        fp = fingerprint(link)

        if fp not in first_pass_set:

            history[fp] = update_history(
                history,
                link,
                None,
                now,
            )

    save_history(
        history
    )

    # -----------------------------
    # Select finalists
    # -----------------------------

    first_pass_sorted = sorted(
        first_pass,
        key=lambda item: item[1],
    )

    finalist_limit = int(
        CFG["finalist_limit"]
    )

    finalists = [
        link
        for link, _
        in first_pass_sorted[
            :finalist_limit
        ]
    ]

    print(
        "Finalists: "
        f"{len(finalists)}"
    )

    # -----------------------------
    # Final repeated verification
    # -----------------------------

    final_results = (
        await run_final_pass(
            finalists
        )
    )

    # -----------------------------
    # Update history with final tests
    # -----------------------------

    for link, latencies in (
        final_results.items()
    ):

        for latency in latencies:

            history[
                fingerprint(link)
            ] = update_history(
                history,
                link,
                latency,
                now,
            )

    save_history(
        history
    )

    # -----------------------------
    # Score finalists
    # -----------------------------

    scored: list[dict] = []

    for link, latencies in (
        final_results.items()
    ):

        attempts = int(
            CFG["final_test_attempts"]
        )

        successes = len(
            latencies
        )

        # Minimum final reliability.
        if successes < int(
            CFG["minimum_final_successes"]
        ):
            continue

        if not latencies:
            continue

        # Median is more robust than a single
        # unusually fast measurement.
        ordered = sorted(
            latencies
        )

        middle = len(
            ordered
        ) // 2

        if len(ordered) % 2:
            median_latency = (
                ordered[middle]
            )
        else:
            median_latency = (
                ordered[middle - 1]
                + ordered[middle]
            ) / 2

        fp = fingerprint(
            link
        )

        item = history.get(
            fp,
            {},
        )

        score = calculate_score(
            median_latency,
            item,
            successes,
            attempts,
            now,
        )

        scored.append(
            {
                "link": link,
                "score": score,
                "median_ms": median_latency,
                "best_ms": min(
                    latencies
                ),
                "attempts": attempts,
                "successes": successes,
                "success_rate": (
                    successes
                    / attempts
                ),
                "fingerprint": fp,
            }
        )

    scored.sort(
        key=lambda item: (
            -item["score"],
            item["median_ms"],
        )
    )

    print(
        "Final stable nodes: "
        f"{len(scored)}"
    )

    # -----------------------------
    # Publish
    # -----------------------------

    best20 = scored[:20]
    best50 = scored[:50]
    best100 = scored[:100]

    publish_file(
        "best20.txt",
        best20,
        now,
        len(links),
        len(first_pass),
        len(finalists),
    )

    publish_file(
        "best50.txt",
        best50,
        now,
        len(links),
        len(first_pass),
        len(finalists),
    )

    publish_file(
        "best100.txt",
        best100,
        now,
        len(links),
        len(first_pass),
        len(finalists),
    )

    # -----------------------------
    # Status
    # -----------------------------

    status = {
        "generated_at": now,
        "candidates_discovered": len(
            unique
        ),
        "candidates_tested": len(
            links
        ),
        "first_pass_working": len(
            first_pass
        ),
        "finalists": len(
            finalists
        ),
        "final_stable": len(
            scored
        ),
        "published": {
            "best20": len(
                best20
            ),
            "best50": len(
                best50
            ),
            "best100": len(
                best100
            ),
        },
        "test_url": CFG[
            "test_url"
        ],
        "final_attempts": CFG[
            "final_test_attempts"
        ],
        "minimum_final_successes": CFG[
            "minimum_final_successes"
        ],
        "top": [
            {
                "rank": index + 1,
                "score": round(
                    item["score"],
                    4,
                ),
                "median_latency_ms": round(
                    item["median_ms"],
                    1,
                ),
                "best_latency_ms": round(
                    item["best_ms"],
                    1,
                ),
                "successes": item[
                    "successes"
                ],
                "attempts": item[
                    "attempts"
                ],
                "success_rate": round(
                    item[
                        "success_rate"
                    ],
                    3,
                ),
                "fingerprint": item[
                    "fingerprint"
                ],
            }

            for index, item
            in enumerate(
                scored[:50]
            )
        ],
    }

    (
        OUT / "status.json"
    ).write_text(
        json.dumps(
            status,
            ensure_ascii=False,
            indent=2,
        )
    )

    print()
    print(
        "================================"
    )
    print(
        "BEST50 BUILD COMPLETE"
    )
    print(
        "================================"
    )
    print(
        f"Candidates: "
        f"{len(links)}"
    )
    print(
        f"First-pass working: "
        f"{len(first_pass)}"
    )
    print(
        f"Finalists: "
        f"{len(finalists)}"
    )
    print(
        f"Final stable: "
        f"{len(scored)}"
    )
    print(
        f"Best20: "
        f"{len(best20)}"
    )
    print(
        f"Best50: "
        f"{len(best50)}"
    )
    print(
        f"Best100: "
        f"{len(best100)}"
    )

    return 0


def main() -> None:

    try:
        exit_code = asyncio.run(
            main_async()
        )

    except KeyboardInterrupt:
        exit_code = 130

    except Exception as error:

        print(
            f"FATAL: {error}",
            file=sys.stderr,
        )

        exit_code = 1

    raise SystemExit(
        exit_code
    )


if __name__ == "__main__":
    main()
