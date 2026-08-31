#!/usr/bin/env python3

"""
Best50 v3

Quality-first VLESS subscription builder.

Pipeline:

1. Fetch public VLESS sources.
2. Parse and normalize VLESS.
3. Remove exact and structural duplicates.
4. REAL HTTP test through sing-box.
5. Select finalists.
6. Re-test finalists five times.
7. Combine current and decaying historical reliability.
8. Detect infrastructure families.
9. Apply quality gates.
10. Select Best20 / Best50 / Best100 with diversity constraints.
11. Publish atomically.
12. Preserve previous publication if the new build is invalid.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import socket
import ipaddress
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from urllib.parse import parse_qs, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
CFG = json.loads((ROOT / "config.json").read_text())

OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

SING_BOX = "sing-box"


# =========================================================
# Generic helpers
# =========================================================


def now_ts() -> int:
    return int(time.time())


def fetch(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Best50Builder/3.0",
            "Accept": "*/*",
        },
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()

    text = raw.decode("utf-8", "ignore").strip()

    if "vless://" not in text.lower():
        compact = re.sub(r"\s+", "", text)

        try:
            decoded = base64.b64decode(
                compact + "===",
                validate=False,
            )
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

        match = re.search(
            r"vless://\S+",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        link = match.group(0).rstrip(
            "`,)]}>\"'"
        )

        if link.lower().startswith("vless://"):
            found.append(link)

    return found


def q1(
    query: dict[str, list[str]],
    key: str,
    default: str = "",
) -> str:
    values = query.get(key)

    if not values:
        return default

    return values[0]


def sha(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def fingerprint(link: str) -> str:
    return sha(link)


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def normalize_path(path: str) -> str:
    if not path:
        return "/"

    path = unquote(path)

    if not path.startswith("/"):
        path = "/" + path

    return path


# =========================================================
# VLESS parsing / normalization
# =========================================================


def parse_vless(link: str) -> dict:
    uri = urlsplit(link)

    if uri.scheme.lower() != "vless":
        raise ValueError("not VLESS")

    if not uri.hostname:
        raise ValueError("missing server")

    if not uri.port:
        raise ValueError("missing port")

    if not uri.username:
        raise ValueError("missing UUID")

    query = parse_qs(
        uri.query,
        keep_blank_values=True,
    )

    server = normalize_host(uri.hostname)
    port = uri.port
    uuid = unquote(uri.username).lower()

    transport = q1(
        query,
        "type",
        "tcp",
    ).lower()

    security = q1(
        query,
        "security",
        "",
    ).lower()

    sni = normalize_host(
        q1(query, "sni")
        or q1(query, "host")
        or server
    )

    host = normalize_host(
        q1(query, "host")
    )

    path = normalize_path(
        q1(query, "path", "/")
    )

    flow = q1(query, "flow")

    fingerprint_value = q1(
        query,
        "fp",
    )

    public_key = (
        q1(query, "pbk")
        or q1(query, "publicKey")
    )

    short_id = (
        q1(query, "sid")
        or q1(query, "shortId")
    )

    if transport in {
        "xhttp",
        "splithttp",
        "quic",
        "kcp",
        "raw",
    }:
        raise ValueError(
            f"unsupported transport: {transport}"
        )

    if security not in {
        "",
        "none",
        "tls",
        "reality",
    }:
        raise ValueError(
            f"unsupported security: {security}"
        )

    if security == "reality":
        if not public_key:
            raise ValueError(
                "Reality without public key"
            )

        if not short_id:
            raise ValueError(
                "Reality without short id"
            )

    return {
        "link": link,
        "server": server,
        "port": port,
        "uuid": uuid,
        "transport": transport,
        "security": security,
        "sni": sni,
        "host": host,
        "path": path,
        "flow": flow,
        "fp": fingerprint_value,
        "public_key": public_key,
        "short_id": short_id,
    }


def normalized_fingerprint(node: dict) -> str:
    """
    Same configuration semantics, ignoring endpoint IP/port.

    This catches cases where the same VLESS account is exposed
    through multiple equivalent endpoints.
    """

    value = "|".join(
        [
            node["uuid"],
            node["transport"],
            node["security"],
            node["sni"],
            node["host"],
            node["path"],
            node["flow"],
            node["fp"],
            node["public_key"],
            node["short_id"],
        ]
    )

    return sha(value)


def endpoint_family(node: dict) -> str:
    """
    Groups nodes that are effectively the same endpoint family.
    """

    value = "|".join(
        [
            node["uuid"],
            node["sni"],
            node["host"],
            node["path"],
            node["transport"],
            node["security"],
        ]
    )

    return sha(value)


def domain_family(value: str) -> str:
    """
    Reduce a hostname to its infrastructure/domain family.

    This intentionally removes common service subdomains so that
    several edge names belonging to the same deployment are not
    treated as unrelated infrastructure.

    Examples:
        api.example.com        -> example.com
        node01.example.com     -> example.com
        cdn.example.co.uk      -> example.co.uk

    This is heuristic by design; no external DNS/WHOIS lookup is
    required during the build.
    """

    value = normalize_host(value or "").lower().strip(".")

    if not value:
        return ""

    # IPv4 / IPv6 literals are not domains.
    if re.fullmatch(r"[0-9.]+", value):
        return ""

    if ":" in value and not value.startswith("["):
        return ""

    parts = [
        part
        for part in value.split(".")
        if part
    ]

    if len(parts) <= 2:
        return value

    # Common second-level country-code domains.
    cc2 = {
        "co.uk", "org.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.nz", "com.br", "com.cn",
        "com.tr", "com.ua", "co.jp",
        "co.kr", "com.pl", "com.sg",
    }

    suffix2 = ".".join(parts[-2:])

    if suffix2 in cc2 and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def ip_family(value: str) -> str:
    """
    Return a coarse endpoint network family.

    IPv4:
        1.2.3.4 -> 1.2.3.0/24

    IPv6:
        normalized first /64-like prefix.

    The purpose is not geolocation. It is to recognize multiple
    endpoints that are very likely part of the same deployment.
    """

    value = (value or "").strip()

    if not value:
        return ""

    try:
        import ipaddress

        address = ipaddress.ip_address(value)

        if address.version == 4:
            network = ipaddress.ip_network(
                f"{address}/24",
                strict=False,
            )
            return str(network)

        network = ipaddress.ip_network(
            f"{address}/64",
            strict=False,
        )
        return str(network)

    except ValueError:
        return ""


def infrastructure_fingerprint(node: dict) -> str:
    """
    Infrastructure-level grouping v3.2.

    The infrastructure identity deliberately does NOT include UUID.

    A VLESS UUID is an account credential, not infrastructure. Multiple
    UUIDs can legitimately belong to the same server/deployment.

    Identity is derived according to transport/security:

    Reality:
        PBK + SID + SNI + transport + security

        This is the strongest practical deterministic identity for a
        Reality deployment. Different edge IPs, ports and UUIDs do not
        fragment the same deployment.

    TLS/WS and plain WS:
        host/SNI + normalized path + transport + security

        For Cloudflare Workers, the Worker hostname is the important
        deployment identity; Cloudflare edge IPs are deliberately ignored.

    Direct TCP / other transports:
        server network family + transport + security

        When a hostname exists, its domain family is preferred.

    The function intentionally avoids using UUID as an infrastructure
    discriminator.
    """

    server = (
        node.get("server")
        or ""
    ).strip().lower()

    sni = normalize_host(
        node.get("sni")
        or ""
    ).lower().strip(".")

    host = normalize_host(
        node.get("host")
        or ""
    ).lower().strip(".")

    path = normalize_path(
        node.get("path")
        or ""
    )

    transport = (
        node.get("transport")
        or ""
    ).strip().lower()

    security = (
        node.get("security")
        or ""
    ).strip().lower()

    public_key = (
        node.get("public_key")
        or ""
    ).strip()

    short_id = (
        node.get("short_id")
        or ""
    ).strip()

    # -----------------------------------------------------
    # Reality
    # -----------------------------------------------------
    #
    # PBK + SID identify the Reality server configuration.
    # SNI identifies the configured target/server profile.
    #
    # UUID is intentionally excluded.
    #
    if security == "reality":

        identity = "|".join(
            [
                "reality",
                transport,
                security,
                public_key,
                short_id,
                sni,
            ]
        )

        return sha(identity)

    # -----------------------------------------------------
    # WebSocket / HTTP-style transports
    # -----------------------------------------------------
    #
    # For WS, the Host + Path normally identify the deployed
    # application/proxy. Do not use Cloudflare edge IP as the
    # primary identity.
    #
    if transport in {
        "ws",
        "http",
        "httpupgrade",
    }:

        deployment_host = (
            host
            or sni
            or server
        )

        # Exact hostname is stronger than the heuristic domain
        # family for Worker-style deployments. In particular,
        # do NOT collapse every *.workers.dev host into one group.
        identity = "|".join(
            [
                "web",
                transport,
                security,
                deployment_host,
                path,
            ]
        )

        return sha(identity)

    # -----------------------------------------------------
    # Other transports
    # -----------------------------------------------------

    domain = (
        domain_family(sni)
        or domain_family(host)
    )

    network = ip_family(server)

    if domain:
        identity = "|".join(
            [
                "domain",
                domain,
                transport,
                security,
            ]
        )

    elif network:
        identity = "|".join(
            [
                "network",
                network,
                transport,
                security,
            ]
        )

    else:
        identity = "|".join(
            [
                "server",
                server,
                transport,
                security,
            ]
        )

    return sha(identity)


# =========================================================
# Country filtering
# =========================================================

ALLOWED_COUNTRIES = set(
    CFG.get("countries", {}).get(
        "allow",
        ["US", "DE", "PL", "NL"],
    )
)

COUNTRY_LABELS = {
    "US": [
        "US", "USA", "UNITED STATES", "AMERICA",
        "NEW YORK", "LOS ANGELES", "CHICAGO",
        "DALLAS", "MIAMI", "SEATTLE", "VIRGINIA",
        "CALIFORNIA", "TEXAS",
    ],
    "DE": [
        "DE", "GERMANY", "DEUTSCHLAND",
        "BERLIN", "FRANKFURT", "NUREMBERG",
        "HAMBURG", "MUNICH", "MUNSTER",
    ],
    "PL": [
        "PL", "POLAND", "POLSKA",
        "WARSAW", "WARSZAWA", "KRAKOW",
        "WROCLAW", "POZNAN",
    ],
    "NL": [
        "NL", "NETHERLANDS", "NEDERLAND",
        "HOLLAND", "AMSTERDAM", "ROTTERDAM",
        "EINDHOVEN", "FLEVO",
    ],
}


def infer_country_from_label(link: str) -> str:
    """
    Infer country from the complete VLESS URI/remark.

    This is only a fallback. Endpoint GeoIP is preferred.
    """
    text = unquote(link).upper()

    if "#" in text:
        remark = text.rsplit("#", 1)[1]
    else:
        remark = text

    # Explicit ISO code gets priority.
    for country, labels in COUNTRY_LABELS.items():
        for label in labels:
            if re.search(
                rf"(?<![A-Z]){re.escape(label)}(?![A-Z])",
                remark,
            ):
                return country

    # Search whole URI as fallback.
    for country, labels in COUNTRY_LABELS.items():
        for label in labels:
            if re.search(
                rf"(?<![A-Z]){re.escape(label)}(?![A-Z])",
                text,
            ):
                return country

    return "XX"


def resolve_endpoint_ip(host: str) -> str:
    """
    Resolve endpoint hostname to an IP.

    For literal IPs no DNS is required.
    """
    host = normalize_host(host)

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        # Prefer IPv4 because public GeoIP APIs generally handle it
        # more consistently.
        for family, _, _, _, sockaddr in infos:
            address = sockaddr[0]

            if family == socket.AF_INET:
                return address

        if infos:
            return infos[0][4][0]

    except Exception:
        pass

    return ""


_GEOIP_DATABASES = None


def _geoip_database_paths() -> tuple[Path, Path]:
    country_cfg = CFG.get(
        "countries",
        {},
    )

    root = Path(
        __file__
    ).resolve().parents[1]

    ipv4_path = root / country_cfg.get(
        "geoip_db_ipv4",
        "data/geoip/server-country-ipv4.csv",
    )

    ipv6_path = root / country_cfg.get(
        "geoip_db_ipv6",
        "data/geoip/server-country-ipv6.csv",
    )

    return (
        ipv4_path,
        ipv6_path,
    )


def _load_geoip_ranges(
    path: Path,
    expected_version: int,
) -> tuple[
    list[int],
    list[int],
    list[str],
]:
    import csv

    starts: list[int] = []
    ends: list[int] = []
    countries: list[str] = []

    if not path.is_file():
        raise RuntimeError(
            "Local GeoIP database is missing: "
            f"{path}. Run: "
            "python scripts/update_geoip.py"
        )

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as handle:
        reader = csv.reader(
            handle
        )

        for row in reader:
            if len(row) < 3:
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
                start_ip.version
                != expected_version
                or end_ip.version
                != expected_version
            ):
                continue

            country = (
                row[2]
                .strip()
                .upper()
            )

            if not re.fullmatch(
                r"[A-Z]{2}",
                country,
            ):
                country = "XX"

            starts.append(
                int(start_ip)
            )

            ends.append(
                int(end_ip)
            )

            countries.append(
                country
            )

    if not starts:
        raise RuntimeError(
            "Local GeoIP database contains "
            f"no usable ranges: {path}"
        )

    # The upstream database is sorted.
    # Verify this because binary lookup depends on it.
    if any(
        starts[index]
        < starts[index - 1]
        for index in range(
            1,
            len(starts),
        )
    ):
        raise RuntimeError(
            "Local GeoIP database is not sorted: "
            f"{path}"
        )

    return (
        starts,
        ends,
        countries,
    )


def _load_geoip_databases():
    global _GEOIP_DATABASES

    if _GEOIP_DATABASES is not None:
        return _GEOIP_DATABASES

    ipv4_path, ipv6_path = (
        _geoip_database_paths()
    )

    print(
        "Loading local server-country "
        "GeoIP database..."
    )

    ipv4 = _load_geoip_ranges(
        ipv4_path,
        4,
    )

    ipv6 = _load_geoip_ranges(
        ipv6_path,
        6,
    )

    _GEOIP_DATABASES = {
        4: ipv4,
        6: ipv6,
    }

    print(
        "Local GeoIP loaded: "
        f"IPv4={len(ipv4[0])} ranges, "
        f"IPv6={len(ipv6[0])} ranges"
    )

    return _GEOIP_DATABASES


def geoip_country(ip: str) -> str:
    """
    Resolve endpoint country using the local
    sapics/ip-location-db server-country database.

    No external GeoIP API request is performed.

    Returns ISO-3166 alpha-2 or XX.
    """
    import bisect

    if not ip:
        return "XX"

    try:
        address = ipaddress.ip_address(
            ip
        )

    except ValueError:
        return "XX"

    databases = (
        _load_geoip_databases()
    )

    starts, ends, countries = (
        databases[address.version]
    )

    value = int(address)

    index = (
        bisect.bisect_right(
            starts,
            value,
        )
        - 1
    )

    if index < 0:
        return "XX"

    if value > ends[index]:
        return "XX"

    country = countries[
        index
    ]

    return (
        country
        if re.fullmatch(
            r"[A-Z]{2}",
            country,
        )
        else "XX"
    )


def classify_country(
    link: str,
    server: str,
) -> tuple[str, str, str]:
    """
    Return:
        country,
        method,
        endpoint_ip

    Strict policy:
      1. Resolve endpoint.
      2. GeoIP endpoint.
      3. If GeoIP unavailable, optionally use explicit source label.
      4. Unknown remains XX and is rejected.

    This prevents accidental publication of arbitrary countries.
    """
    endpoint_ip = resolve_endpoint_ip(server)

    if endpoint_ip:
        country = geoip_country(endpoint_ip)

        if country in ALLOWED_COUNTRIES:
            return country, "geoip", endpoint_ip

        # A known non-allowed country is a HARD rejection.
        if country != "XX":
            return country, "geoip", endpoint_ip

    if CFG.get("countries", {}).get(
        "label_fallback",
        True,
    ):
        label_country = infer_country_from_label(link)

        if label_country in ALLOWED_COUNTRIES:
            return label_country, "label", endpoint_ip

    return "XX", "unknown", endpoint_ip



async def classify_countries_batch(
    candidates: list[tuple[str, dict]],
) -> list[dict]:
    """
    Strict concurrent country classification.

    Acceptance policy is intentionally identical to classify_country():

      1. Resolve the real endpoint hostname/IP.
      2. GeoIP the resolved endpoint.
      3. A known non-allowed country is a HARD rejection.
      4. Label fallback is allowed only when GeoIP is unavailable/XX.
      5. Only ALLOWED_COUNTRIES can leave this function.

    Performance strategy:

      - DNS is performed once per unique server.
      - GeoIP is performed once per unique resolved IP.
      - GeoIP lookups are local binary searches with no API quota.
      - Blocking DNS runs outside the asyncio event loop.
      - dns_concurrency limits DNS concurrency.
    """
    if not candidates:
        return []

    country_cfg = CFG.get("countries", {})

    dns_concurrency = max(
        1,
        int(
            country_cfg.get(
                "dns_concurrency",
                40,
            )
        ),
    )

    semaphore = asyncio.Semaphore(
        dns_concurrency
    )

    # -----------------------------------------------------
    # Phase 1: DNS
    # -----------------------------------------------------

    unique_servers = list(
        dict.fromkeys(
            normalize_host(
                node["server"]
            )
            for _, node in candidates
        )
    )

    print(
        "Country classification: "
        f"{len(candidates)} candidates, "
        f"{len(unique_servers)} unique endpoints, "
        f"dns_concurrency={dns_concurrency}"
    )

    server_to_ip: dict[str, str] = {}

    async def resolve_one(
        server: str,
    ) -> tuple[str, str]:
        async with semaphore:
            try:
                endpoint_ip = (
                    await asyncio.to_thread(
                        resolve_endpoint_ip,
                        server,
                    )
                )
            except Exception:
                endpoint_ip = ""

        return server, endpoint_ip

    dns_tasks = [
        asyncio.create_task(
            resolve_one(server)
        )
        for server in unique_servers
    ]

    dns_total = len(dns_tasks)

    for completed, task in enumerate(
        asyncio.as_completed(
            dns_tasks
        ),
        start=1,
    ):
        server, endpoint_ip = await task

        server_to_ip[
            server
        ] = endpoint_ip

        if (
            completed == 1
            or completed % 250 == 0
            or completed == dns_total
        ):
            print(
                "Country DNS: "
                f"{completed}/{dns_total}"
            )

    # -----------------------------------------------------
    # Phase 2: Local GeoIP
    # -----------------------------------------------------

    unique_ips = list(
        dict.fromkeys(
            endpoint_ip
            for endpoint_ip
            in server_to_ip.values()
            if endpoint_ip
        )
    )

    ip_to_country: dict[str, str] = {}

    geo_total = len(
        unique_ips
    )

    print(
        "Country GeoIP local: "
        f"0/{geo_total}"
    )

    for completed, endpoint_ip in enumerate(
        unique_ips,
        start=1,
    ):
        try:
            country = geoip_country(
                endpoint_ip
            )

        except Exception:
            country = "XX"

        ip_to_country[
            endpoint_ip
        ] = country

        if (
            completed == 1
            or completed % 1000 == 0
            or completed == geo_total
        ):
            print(
                "Country GeoIP local: "
                f"{completed}/{geo_total}"
            )

    # -----------------------------------------------------
    # Phase 3: Apply EXACTLY the existing strict policy.
    # -----------------------------------------------------

    accepted: list[dict] = []

    method_counts = {
        "geoip": 0,
        "label": 0,
        "rejected": 0,
        "unknown": 0,
    }

    country_counts: dict[str, int] = {}

    label_fallback = bool(
        country_cfg.get(
            "label_fallback",
            True,
        )
    )

    for link, node in candidates:
        server = normalize_host(
            node["server"]
        )

        endpoint_ip = server_to_ip.get(
            server,
            "",
        )

        geo_country = (
            ip_to_country.get(
                endpoint_ip,
                "XX",
            )
            if endpoint_ip
            else "XX"
        )

        country = "XX"
        country_method = "unknown"

        # Known GeoIP result.
        if geo_country != "XX":
            country = geo_country
            country_method = "geoip"

        # GeoIP unavailable:
        # preserve the existing explicit-label fallback.
        elif label_fallback:
            label_country = (
                infer_country_from_label(
                    link
                )
            )

            if (
                label_country
                in ALLOWED_COUNTRIES
            ):
                country = label_country
                country_method = "label"

        # HARD FILTER remains unchanged.
        if country not in ALLOWED_COUNTRIES:
            method_counts["rejected"] += 1

            if country == "XX":
                method_counts["unknown"] += 1

            continue

        node["country"] = country
        node[
            "country_method"
        ] = country_method
        node[
            "endpoint_ip"
        ] = endpoint_ip

        node[
            "endpoint_family"
        ] = endpoint_family(
            node
        )

        node[
            "infrastructure"
        ] = infrastructure_fingerprint(
            node
        )

        accepted.append(
            node
        )

        method_counts[
            country_method
        ] = (
            method_counts.get(
                country_method,
                0,
            )
            + 1
        )

        country_counts[
            country
        ] = (
            country_counts.get(
                country,
                0,
            )
            + 1
        )

    print(
        "Country classification complete: "
        f"{len(accepted)}/{len(candidates)} accepted"
    )

    print(
        "Country methods: "
        f"geoip={method_counts['geoip']}, "
        f"label={method_counts['label']}, "
        f"rejected={method_counts['rejected']}, "
        f"unknown={method_counts['unknown']}"
    )

    print(
        "Country distribution: "
        + ", ".join(
            f"{country}={country_counts.get(country, 0)}"
            for country
            in sorted(
                ALLOWED_COUNTRIES
            )
        )
    )

    return accepted



# =========================================================
# VLESS -> sing-box
# =========================================================


def vless_to_singbox(
    node: dict,
    tag: str = "node",
) -> dict:

    outbound = {
        "type": "vless",
        "tag": tag,
        "server": node["server"],
        "server_port": node["port"],
        "uuid": node["uuid"],
    }

    if node["flow"]:
        outbound["flow"] = node["flow"]

    transport = node["transport"]
    security = node["security"]

    if security in {"tls", "reality"}:

        tls = {
            "enabled": True,
            "server_name": (
                node["sni"]
                or node["server"]
            ),
        }

        if node["fp"]:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": node["fp"],
            }

        if security == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": node["public_key"],
                "short_id": node["short_id"],
            }

        outbound["tls"] = tls

    if transport == "ws":

        headers = {}

        if node["host"]:
            headers["Host"] = node["host"]

        outbound["transport"] = {
            "type": "ws",
            "path": node["path"],
            "headers": headers,
        }

    elif transport == "grpc":

        query = parse_qs(
            urlsplit(node["link"]).query,
            keep_blank_values=True,
        )

        service_name = unquote(
            q1(
                query,
                "serviceName",
                "",
            )
        )

        outbound["transport"] = {
            "type": "grpc",
        }

        # service_name is optional in sing-box.
        # Preserve it when explicitly provided.
        if service_name:
            outbound["transport"][
                "service_name"
            ] = service_name

    elif transport == "http":

        outbound["transport"] = {
            "type": "http",
            "path": node["path"],
            "host": (
                [node["host"]]
                if node["host"]
                else []
            ),
        }

    elif transport == "httpupgrade":

        headers = {}

        if node["host"]:
            headers["Host"] = node["host"]

        outbound["transport"] = {
            "type": "httpupgrade",
            "path": node["path"],
            "headers": headers,
        }

    elif transport == "tcp":

        query = parse_qs(
            urlsplit(node["link"]).query,
            keep_blank_values=True,
        )

        header_type = q1(
            query,
            "headerType",
            "",
        ).lower()

        if header_type == "http":

            outbound["transport"] = {
                "type": "http",
                "host": (
                    [node["host"]]
                    if node["host"]
                    else []
                ),
                "path": node["path"],
            }

        elif header_type not in {
            "",
            "none",
        }:
            raise ValueError(
                f"unsupported TCP headerType: {header_type}"
            )

    return outbound


# =========================================================
# Process execution
# =========================================================


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


# =========================================================
# Real proxy probe
# =========================================================


async def _probe_batch_in_slot(
    items: list[tuple[int, str]],
    slot: int,
) -> list[tuple[str, float | None]]:
    """
    Probe multiple VLESS nodes through one sing-box instance.

    Each candidate has:
      - its own SOCKS inbound;
      - its own VLESS outbound;
      - an explicit inbound -> outbound route rule.

    If sing-box rejects the combined configuration, recursively
    split the batch until malformed candidates are isolated.
    """

    if not items:
        return []

    engine = CFG.get(
        "probe_engine",
        {},
    )

    batch_size = max(
        1,
        int(engine.get("batch_size", 64)),
    )

    startup_delay = float(
        engine.get("startup_delay", 0.35)
    )

    curl_parallel = max(
        1,
        int(engine.get("curl_parallel", 64)),
    )

    base_port = (
        int(engine.get("base_port", 22000))
        + slot * (batch_size + 32)
    )

    valid: list[
        tuple[int, str, int]
    ] = []

    immediate: list[
        tuple[str, float | None]
    ] = []

    inbounds = []
    outbounds = []
    rules = []

    for _, link in items:

        try:
            node = parse_vless(link)

            local_index = len(valid)

            inbound_tag = (
                f"probe-in-{local_index}"
            )

            outbound_tag = (
                f"probe-out-{local_index}"
            )

            outbound = vless_to_singbox(
                node,
                tag=outbound_tag,
            )

        except Exception:
            immediate.append(
                (link, None)
            )
            continue

        port = base_port + local_index

        valid.append(
            (
                local_index,
                link,
                port,
            )
        )

        inbounds.append(
            {
                "type": "socks",
                "tag": inbound_tag,
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )

        outbounds.append(
            outbound
        )

        rules.append(
            {
                "inbound": [
                    inbound_tag
                ],
                "action": "route",
                "outbound": outbound_tag,
            }
        )

    if not valid:
        return immediate

    outbounds.append(
        {
            "type": "direct",
            "tag": "direct",
        }
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
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": "direct",
        },
    }

    with tempfile.TemporaryDirectory() as temp_dir:

        config_path = (
            Path(temp_dir)
            / "config.json"
        )

        config_path.write_text(
            json.dumps(
                config,
                ensure_ascii=False,
            )
        )

        check_code, _, _ = (
            await run_process(
                [
                    SING_BOX,
                    "check",
                    "-c",
                    str(config_path),
                ],
                15,
            )
        )

        if check_code != 0:

            links_only = [
                link
                for _, link, _
                in valid
            ]

            if len(links_only) == 1:
                return (
                    immediate
                    + [
                        (
                            links_only[0],
                            None,
                        )
                    ]
                )

            middle = max(
                1,
                len(links_only) // 2,
            )

            left_items = [
                (
                    index,
                    link,
                )
                for index, link
                in enumerate(
                    links_only[:middle]
                )
            ]

            right_items = [
                (
                    index,
                    link,
                )
                for index, link
                in enumerate(
                    links_only[middle:]
                )
            ]

            left = (
                await _probe_batch_in_slot(
                    left_items,
                    slot,
                )
            )

            right = (
                await _probe_batch_in_slot(
                    right_items,
                    slot,
                )
            )

            return (
                immediate
                + left
                + right
            )

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

            await asyncio.sleep(
                startup_delay
            )

            if process.returncode is not None:

                return (
                    immediate
                    + [
                        (
                            link,
                            None,
                        )
                        for _, link, _
                        in valid
                    ]
                )

            sem = asyncio.Semaphore(
                curl_parallel
            )

            connect_timeout = str(
                CFG["first_pass"][
                    "connect_timeout"
                ]
            )

            request_timeout = float(
                CFG["first_pass"][
                    "request_timeout"
                ]
            )

            async def probe_via_port(
                link: str,
                port: int,
            ) -> tuple[
                str,
                float | None,
            ]:

                async with sem:

                    started = (
                        time.perf_counter()
                    )

                    code, output, _ = (
                        await run_process(
                            [
                                "curl",
                                "--socks5-hostname",
                                (
                                    "127.0.0.1:"
                                    f"{port}"
                                ),
                                "--connect-timeout",
                                connect_timeout,
                                "--max-time",
                                str(
                                    request_timeout
                                ),
                                "-sS",
                                "-o",
                                "/dev/null",
                                "-w",
                                "%{http_code}",
                                CFG["test_url"],
                            ],
                            request_timeout + 3,
                        )
                    )

                    elapsed = (
                        time.perf_counter()
                        - started
                    ) * 1000.0

                    http_code = (
                        output
                        .decode(
                            errors="ignore"
                        )
                        .strip()
                    )

                    if (
                        code == 0
                        and re.match(
                            r"^[23]\d\d$",
                            http_code,
                        )
                    ):
                        return (
                            link,
                            elapsed,
                        )

                    return (
                        link,
                        None,
                    )

            results = (
                await asyncio.gather(
                    *(
                        probe_via_port(
                            link,
                            port,
                        )
                        for _, link, port
                        in valid
                    )
                )
            )

            return (
                immediate
                + list(results)
            )

        finally:

            if process.returncode is None:

                try:
                    process.terminate()
                except ProcessLookupError:
                    pass

                try:
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=2,
                    )

                except asyncio.TimeoutError:

                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass

                    try:
                        await process.wait()
                    except Exception:
                        pass


async def run_probe_batches(
    links: list[str],
    label: str,
) -> list[
    tuple[str, float | None]
]:
    """
    Probe links in bounded batches.

    parallel_batches sing-box instances are active at once.
    Each instance owns its own non-overlapping port range.
    """

    if not links:
        return []

    engine = CFG.get(
        "probe_engine",
        {},
    )

    batch_size = max(
        1,
        int(
            engine.get(
                "batch_size",
                64,
            )
        ),
    )

    parallel_batches = max(
        1,
        int(
            engine.get(
                "parallel_batches",
                4,
            )
        ),
    )

    chunks = []

    for start in range(
        0,
        len(links),
        batch_size,
    ):

        chunk = [
            (
                index,
                links[index],
            )
            for index in range(
                start,
                min(
                    start + batch_size,
                    len(links),
                ),
            )
        ]

        chunks.append(
            chunk
        )

    slot_queue: asyncio.Queue[int] = (
        asyncio.Queue()
    )

    for slot in range(
        parallel_batches
    ):
        slot_queue.put_nowait(
            slot
        )

    async def run_chunk(
        chunk,
    ):
        slot = (
            await slot_queue.get()
        )

        try:
            return (
                await _probe_batch_in_slot(
                    chunk,
                    slot,
                )
            )
        finally:
            slot_queue.put_nowait(
                slot
            )

    tasks = [
        asyncio.create_task(
            run_chunk(chunk)
        )
        for chunk in chunks
    ]

    results = []

    tested = 0
    working = 0

    total_batches = len(tasks)

    for completed, task in enumerate(
        asyncio.as_completed(tasks),
        start=1,
    ):

        batch_results = await task

        results.extend(
            batch_results
        )

        tested += len(
            batch_results
        )

        working += sum(
            1
            for _, latency
            in batch_results
            if latency is not None
        )

        if (
            completed == 1
            or completed % 10 == 0
            or completed == total_batches
        ):
            print(
                f"{label}: "
                f"{tested}/{len(links)} tested, "
                f"{working} working, "
                f"{completed}/{total_batches} batches"
            )

    return results



# =========================================================
# History
# =========================================================


def load_history() -> dict:

    path = (
        ROOT
        / CFG["history"]["file"]
    )

    if not path.exists():
        return {}

    try:
        return json.loads(
            path.read_text()
        )

    except Exception:
        return {}


def save_history(history: dict) -> None:

    path = (
        ROOT
        / CFG["history"]["file"]
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
            "observations": [],
        },
    )

    if latency is not None:

        item["successes"] = (
            int(item.get("successes", 0)) + 1
        )

        item["last_success"] = now

        if item.get("best_ms") is None:
            item["best_ms"] = latency
        else:
            item["best_ms"] = min(
                float(item["best_ms"]),
                latency,
            )

        latencies = list(
            item.get("latencies", [])
        )

        latencies.append(
            round(latency, 1)
        )

        item["latencies"] = latencies[
            -CFG["history"]["max_latency_samples"]:
        ]

        observations = list(
            item.get("observations", [])
        )

        observations.append(
            {
                "ts": now,
                "success": True,
                "latency": round(
                    latency,
                    1,
                ),
            }
        )

        item["observations"] = observations[-100:]

    else:

        item["failures"] = (
            int(item.get("failures", 0)) + 1
        )

        item["last_failure"] = now

        observations = list(
            item.get("observations", [])
        )

        observations.append(
            {
                "ts": now,
                "success": False,
                "latency": None,
            }
        )

        item["observations"] = observations[-100:]

    return item


def decayed_history_stats(
    item: dict,
    now: int,
) -> tuple[float, float]:

    observations = item.get(
        "observations",
        [],
    )

    if not observations:
        return 0.0, 0.0

    decay_seconds = (
        CFG["history"]["decay_days"]
        * 86400
    )

    weighted_success = 0.0
    weighted_total = 0.0
    weighted_latency = 0.0

    for observation in observations:

        ts = int(
            observation.get(
                "ts",
                now,
            )
        )

        age = max(
            0,
            now - ts,
        )

        weight = math.exp(
            -age / decay_seconds
        )

        weighted_total += weight

        if observation.get(
            "success",
            False,
        ):
            weighted_success += weight

            latency = observation.get(
                "latency"
            )

            if latency is not None:
                weighted_latency += (
                    float(latency)
                    * weight
                )

    if weighted_total <= 0:
        return 0.0, 0.0

    reliability = (
        weighted_success
        / weighted_total
    )

    average_latency = (
        weighted_latency
        / weighted_success
        if weighted_success > 0
        else 0.0
    )

    return reliability, average_latency


# =========================================================
# Statistics
# =========================================================


def percentile(
    values: list[float],
    p: float,
) -> float:

    if not values:
        return float("inf")

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    index = (
        (len(values) - 1)
        * p
    )

    low = math.floor(index)
    high = math.ceil(index)

    if low == high:
        return values[low]

    fraction = index - low

    return (
        values[low]
        + (
            values[high]
            - values[low]
        )
        * fraction
    )


def jitter_ratio(
    values: list[float],
) -> float:

    if len(values) < 2:
        return 0.0

    med = median(values)

    if med <= 0:
        return float("inf")

    deviations = [
        abs(value - med)
        for value in values
    ]

    return (
        median(deviations)
        / med
    )


# =========================================================
# Scoring
# =========================================================


def calculate_score(
    current_latencies: list[float],
    history_item: dict,
    now: int,
) -> tuple[float, dict]:

    successes = len(
        current_latencies
    )

    attempts = CFG["final_pass"]["attempts"]

    current_reliability = (
        successes / attempts
        if attempts
        else 0.0
    )

    historical_reliability, historical_latency = (
        decayed_history_stats(
            history_item,
            now,
        )
    )

    if historical_reliability == 0:
        historical_reliability = (
            current_reliability
        )

    med = median(
        current_latencies
    )

    p95 = percentile(
        current_latencies,
        0.95,
    )

    minimum = min(
        current_latencies
    )

    maximum = max(
        current_latencies
    )

    jitter = jitter_ratio(
        current_latencies
    )

    latency_score = max(
        0.0,
        1.0 - med / 1500.0,
    )

    stability_score = max(
        0.0,
        1.0 - min(
            jitter,
            1.0,
        ),
    )

    if p95 > 5000:
        stability_score *= 0.25

    last_success = int(
        history_item.get(
            "last_success",
            now,
        )
    )

    age_hours = max(
        0,
        now - last_success,
    ) / 3600

    recency = max(
        0.0,
        1.0 - age_hours / 72.0,
    )

    reliability = (
        current_reliability * 0.65
        + historical_reliability * 0.35
    )

    score = (
        reliability * 0.35
        + historical_reliability * 0.20
        + latency_score * 0.20
        + stability_score * 0.10
        + recency * 0.05
        + 0.05
        + 0.05
    )

    metrics = {
        "score": round(
            score,
            6,
        ),
        "current_successes": successes,
        "current_attempts": attempts,
        "current_success_rate": round(
            current_reliability,
            4,
        ),
        "historical_success_rate": round(
            historical_reliability,
            4,
        ),
        "median_latency_ms": round(
            med,
            1,
        ),
        "p95_latency_ms": round(
            p95,
            1,
        ),
        "best_latency_ms": round(
            minimum,
            1,
        ),
        "worst_latency_ms": round(
            maximum,
            1,
        ),
        "jitter_ratio": round(
            jitter,
            4,
        ),
        "historical_latency_ms": round(
            historical_latency,
            1,
        ),
        "recency": round(
            recency,
            4,
        ),
    }

    return score, metrics


# =========================================================
# First-pass finalist ranking
# =========================================================


def calculate_first_pass_priority(
    latency: float,
    history_item: dict,
    now: int,
) -> float:
    """
    Rank first-pass nodes before expensive repeated testing.

    The old v3 implementation selected finalists using only the
    first observed latency. That wastes the historical reliability
    signal already collected in history.json.

    This is intentionally not the final score. It is only a
    cheap pre-filter used to decide which nodes deserve the
    repeated 5-attempt verification.
    """

    historical_reliability, historical_latency = (
        decayed_history_stats(
            history_item,
            now,
        )
    )

    if historical_reliability <= 0:
        historical_reliability = 0.5

    if historical_latency <= 0:
        historical_latency = latency

    current_latency_score = max(
        0.0,
        1.0 - latency / 2500.0,
    )

    historical_latency_score = max(
        0.0,
        1.0 - historical_latency / 2500.0,
    )

    # Historical reliability is deliberately useful but cannot
    # completely dominate a fresh real-time measurement.
    score = (
        current_latency_score * 0.55
        + historical_reliability * 0.30
        + historical_latency_score * 0.15
    )

    return score


# =========================================================
# First pass / final pass
# =========================================================


async def run_first_pass(
    links: list[str],
) -> list[tuple[str, float]]:

    results = await run_probe_batches(
        links,
        "First pass",
    )

    return [
        (
            link,
            latency,
        )
        for link, latency
        in results
        if latency is not None
    ]


async def run_final_pass(
    links: list[str],
) -> dict[str, list[float]]:

    final = {
        link: []
        for link in links
    }

    attempts = CFG[
        "final_pass"
    ]["attempts"]

    for round_number in range(
        attempts
    ):

        print(
            f"Final verification "
            f"{round_number + 1}/{attempts}"
        )

        results = (
            await run_probe_batches(
                links,
                (
                    "Final "
                    f"{round_number + 1}"
                ),
            )
        )

        for link, latency in results:

            if latency is not None:
                final[link].append(
                    latency
                )

    return final


# =========================================================
# Quality
# =========================================================


def quality_gate(
    latencies: list[float],
) -> bool:

    if not latencies:
        return False

    minimum_successes = (
        CFG["final_pass"][
            "minimum_successes"
        ]
    )

    if len(latencies) < minimum_successes:
        return False

    med = median(latencies)

    p95 = percentile(
        latencies,
        0.95,
    )

    jitter = jitter_ratio(
        latencies
    )

    quality = CFG["quality"]

    if med > quality[
        "max_median_latency_ms"
    ]:
        return False

    if p95 > quality[
        "max_p95_latency_ms"
    ]:
        return False

    if jitter > quality[
        "max_jitter_ratio"
    ]:
        return False

    return True


# =========================================================
# Diversity-aware selection
# =========================================================


def select_diverse(
    ranked: list[dict],
    limit: int,
) -> list[dict]:
    """
    Quality-first diversity selector.

    IMPORTANT:
    `ranked` already contains only nodes which passed the
    repeated final quality verification.

    Therefore diversity must improve resilience and ordering,
    but it must not unnecessarily shrink the published list.

    Selection happens in two stages:

    Stage 1:
        Apply configured infrastructure/country limits and
        diversity penalties.

    Stage 2:
        If Stage 1 cannot fill the requested publication,
        fill the remaining positions from the highest-scoring
        already quality-qualified nodes.

    No node bypasses:
        - protocol parsing,
        - structural deduplication,
        - strict country filtering,
        - first real HTTP test,
        - repeated final verification,
        - quality_gate().
    """

    if limit <= 0 or not ranked:
        return []

    target = min(
        limit,
        len(ranked),
    )

    selected: list[dict] = []

    selected_links = set()

    infra_counts = Counter()
    country_counts = Counter()
    family_counts = Counter()

    if limit <= 20:

        max_infra = CFG[
            "diversity"
        ][
            "max_same_infrastructure_best20"
        ]

        max_country = CFG[
            "diversity"
        ][
            "max_same_country_best20"
        ]

    elif limit <= 50:

        max_infra = CFG[
            "diversity"
        ][
            "max_same_infrastructure_best50"
        ]

        max_country = CFG[
            "diversity"
        ][
            "max_same_country_best50"
        ]

    else:

        max_infra = CFG[
            "diversity"
        ][
            "max_same_infrastructure_best100"
        ]

        max_country = CFG[
            "diversity"
        ][
            "max_same_country_best100"
        ]

    # -----------------------------------------------------
    # Stage 1 — strict diversity-aware selection
    # -----------------------------------------------------

    remaining = list(ranked)

    while remaining and len(selected) < target:

        best_index = None
        best_effective = -1.0

        for index, item in enumerate(
            remaining
        ):

            infra = item[
                "infrastructure"
            ]

            country = item[
                "country"
            ]

            family = item[
                "endpoint_family"
            ]

            if infra_counts[infra] >= max_infra:
                continue

            if country_counts[country] >= max_country:
                continue

            effective = float(
                item["score"]
            )

            # Same endpoint family.
            if family_counts[family] > 0:
                effective *= 0.88

            # Same infrastructure.
            if infra_counts[infra] > 0:
                effective *= 0.70

            # Same country.
            if country_counts[country] > 0:
                effective *= 0.97

            if effective > best_effective:

                best_effective = effective
                best_index = index

        if best_index is None:
            break

        item = remaining.pop(
            best_index
        )

        selected.append(item)
        selected_links.add(
            item["link"]
        )

        infra_counts[
            item["infrastructure"]
        ] += 1

        country_counts[
            item["country"]
        ] += 1

        family_counts[
            item["endpoint_family"]
        ] += 1

    strict_count = len(selected)

    # -----------------------------------------------------
    # Stage 2 — quality-qualified fallback
    # -----------------------------------------------------
    #
    # Everything in ranked has ALREADY passed quality_gate().
    #
    # We therefore relax only diversity caps here.
    # Quality and country policy are never relaxed.
    # -----------------------------------------------------

    if len(selected) < target:

        for item in ranked:

            if len(selected) >= target:
                break

            if item["link"] in selected_links:
                continue

            selected.append(item)
            selected_links.add(
                item["link"]
            )

            infra_counts[
                item["infrastructure"]
            ] += 1

            country_counts[
                item["country"]
            ] += 1

            family_counts[
                item["endpoint_family"]
            ] += 1

    fallback_count = (
        len(selected)
        - strict_count
    )

    if fallback_count > 0:

        print(
            "Diversity fallback: "
            f"{fallback_count} quality-qualified "
            "nodes added to reach "
            f"{len(selected)}/{target}"
        )

    return selected


# =========================================================
# Publishing
# =========================================================


def publish_file(
    name: str,
    chosen: list[dict],
    now: int,
    stats: dict,
) -> None:

    lines = [
        f"# Best50 v{CFG.get('pipeline_version', '4.4')} — REAL-HTTP-TESTED VLESS",
        "#profile-title: Best50 VPN",
        "#profile-update-interval: 1",
        (
            "# generated: "
            + time.strftime(
                "%Y-%m-%d %H:%M:%S UTC",
                time.gmtime(now),
            )
        ),
        "#",
        f"# candidates: {stats['candidates']}",
        f"# parse_valid: {stats['parse_valid']}",
        f"# exact_duplicates_removed: "
        f"{stats['exact_duplicates_removed']}",
        f"# structural_duplicates_removed: "
        f"{stats['structural_duplicates_removed']}",
        f"# first_pass_working: "
        f"{stats['first_pass_working']}",
        f"# final_tested: "
        f"{stats['final_tested']}",
        f"# final_stable: "
        f"{stats['final_stable']}",
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

    target = OUT / name
    temp = OUT / (
        f".{name}.tmp"
    )

    temp.write_text(
        "\n".join(lines)
        + "\n"
    )

    temp.replace(target)


def write_status(
    status: dict,
) -> None:

    target = OUT / "status.json"
    temp = OUT / ".status.json.tmp"

    temp.write_text(
        json.dumps(
            status,
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
    )

    temp.replace(target)


# =========================================================
# Main
# =========================================================


async def main_async() -> int:

    now = now_ts()

    stats = {
        "candidates": 0,
        "parse_valid": 0,
        "exact_duplicates_removed": 0,
        "structural_duplicates_removed": 0,
        "first_pass_working": 0,
        "final_tested": 0,
        "final_stable": 0,
        "country_filtered": 0,
        "country_distribution": {},
    }

    # -----------------------------------------------------
    # Fetch
    # -----------------------------------------------------

    all_links: list[str] = []

    source_stats = {}

    for source in CFG["sources"]:

        try:

            text = await asyncio.to_thread(
                fetch,
                source["url"],
            )

            links = extract_vless(text)

            source_stats[
                source["name"]
            ] = len(links)

            print(
                f"{source['name']}: "
                f"{len(links)} VLESS candidates"
            )

            all_links.extend(links)

        except Exception as error:

            source_stats[
                source["name"]
            ] = {
                "error": str(error)
            }

            print(
                f"WARNING {source['name']}: "
                f"{error}",
                file=sys.stderr,
            )

    stats["candidates"] = len(all_links)

    if not all_links:

        print(
            "ERROR: no candidates discovered"
        )

        return 1

    # -----------------------------------------------------
    # Exact dedup
    # -----------------------------------------------------

    exact = {}

    for link in all_links:
        exact.setdefault(
            fingerprint(link),
            link,
        )

    stats[
        "exact_duplicates_removed"
    ] = (
        len(all_links)
        - len(exact)
    )

    # -----------------------------------------------------
    # Parse + structural dedup
    # -----------------------------------------------------

    parsed: list[dict] = []
    pre_country: list[tuple[str, dict]] = []
    seen_structural = set()

    for link in exact.values():

        try:
            node = parse_vless(link)

        except Exception:
            continue

        stats["parse_valid"] += 1

        structural = (
            normalized_fingerprint(
                node
            )
        )

        if structural in seen_structural:

            stats[
                "structural_duplicates_removed"
            ] += 1

            continue

        seen_structural.add(
            structural
        )

        # Country classification is intentionally deferred.
        # This preserves the strict filter while allowing blocking
        # DNS/GeoIP work to run concurrently after structural dedup.
        pre_country.append(
            (
                link,
                node,
            )
        )

    parsed = await classify_countries_batch(
        pre_country
    )

    links = [
        node["link"]
        for node in parsed
    ]

    candidate_limit = int(
        CFG["candidate_limit"]
    )

    if (
        candidate_limit > 0
        and len(links) > candidate_limit
    ):
        links = links[
            :candidate_limit
        ]

        allowed = set(links)

        parsed = [
            node
            for node in parsed
            if node["link"] in allowed
        ]

    country_distribution = Counter(
        node["country"]
        for node in parsed
    )

    stats["country_distribution"] = dict(
        country_distribution
    )

    print(
        f"Candidates after strict country filter: "
        f"{len(parsed)}"
    )

    print(
        "Allowed countries: "
        + ", ".join(sorted(ALLOWED_COUNTRIES))
    )

    print(
        "Country distribution: "
        + json.dumps(
            dict(country_distribution),
            sort_keys=True,
        )
    )

    if not parsed:
        print(
            "ERROR: no valid VLESS candidates"
        )
        return 1

    # -----------------------------------------------------
    # First pass
    # -----------------------------------------------------

    benchmark_limit = int(
        os.environ.get(
            "BEST50_BENCHMARK_LIMIT",
            "0",
        )
    )

    if benchmark_limit > 0:

        benchmark_limit = min(
            benchmark_limit,
            len(links),
        )

        step = (
            len(links)
            / benchmark_limit
        )

        benchmark_links = [
            links[
                min(
                    int(index * step),
                    len(links) - 1,
                )
            ]
            for index in range(
                benchmark_limit
            )
        ]

        print()
        print(
            "=== BOUNDED PROBE BENCHMARK ==="
        )
        print(
            f"Candidates: "
            f"{len(benchmark_links)}"
        )

        started = (
            time.perf_counter()
        )

        benchmark_results = (
            await run_first_pass(
                benchmark_links
            )
        )

        elapsed = (
            time.perf_counter()
            - started
        )

        rate = (
            len(benchmark_links)
            / elapsed
            if elapsed > 0
            else 0.0
        )

        projected = (
            len(links)
            / rate
            if rate > 0
            else 0.0
        )

        print()
        print(
            "=== BENCHMARK RESULT ==="
        )
        print(
            f"tested: "
            f"{len(benchmark_links)}"
        )
        print(
            f"working: "
            f"{len(benchmark_results)}"
        )
        print(
            f"elapsed_sec: "
            f"{elapsed:.2f}"
        )
        print(
            f"nodes_per_sec: "
            f"{rate:.2f}"
        )
        print(
            "projected_full_first_pass_sec: "
            f"{projected:.1f}"
        )
        print(
            "projected_full_first_pass_min: "
            f"{projected / 60.0:.2f}"
        )
        print(
            "BENCHMARK ONLY - nothing published"
        )

        return 0

    first_pass = await run_first_pass(
        links
    )

    stats[
        "first_pass_working"
    ] = len(first_pass)

    print(
        f"First-pass working: "
        f"{len(first_pass)}"
    )

    if not first_pass:

        print(
            "ERROR: no working nodes "
            "found; preserving previous "
            "published files."
        )

        return 1

    first_latency = dict(
        first_pass
    )

    # -----------------------------------------------------
    # History
    # -----------------------------------------------------

    history = load_history()

    first_pass_set = set(
        first_latency
    )

    for node in parsed:

        link = node["link"]

        history[
            fingerprint(link)
        ] = update_history(
            history,
            link,
            first_latency.get(link),
            now,
        )

    save_history(history)

    # -----------------------------------------------------
    # Finalists
    # -----------------------------------------------------

    # -----------------------------------------------------
    # Finalists
    #
    # v3.1:
    # Do not select finalists by raw first-pass latency only.
    # Incorporate decayed historical reliability and latency.
    # -----------------------------------------------------

    finalist_candidates = []

    for link, latency in first_pass:

        history_item = history.get(
            fingerprint(link),
            {},
        )

        priority = calculate_first_pass_priority(
            latency,
            history_item,
            now,
        )

        finalist_candidates.append(
            (
                priority,
                latency,
                link,
            )
        )

    finalist_candidates.sort(
        key=lambda item: (
            -item[0],
            item[1],
        )
    )

    finalist_candidates = finalist_candidates[
        : CFG["final_pass"][
            "finalist_limit"
        ]
    ]

    finalist_links = [
        link
        for _, _, link
        in finalist_candidates
    ]

    stats[
        "final_tested"
    ] = len(finalist_links)

    print(
        f"Finalists: "
        f"{len(finalist_links)}"
    )

    # -----------------------------------------------------
    # Final repeated test
    # -----------------------------------------------------

    final_results = await run_final_pass(
        finalist_links
    )

    stable = {}

    for link, latencies in final_results.items():

        if quality_gate(
            latencies
        ):
            stable[link] = latencies

    stats[
        "final_stable"
    ] = len(stable)

    print(
        f"Final stable: "
        f"{len(stable)}"
    )

    if len(stable) < 20:

        print(
            "ERROR: fewer than 20 "
            "quality-qualified nodes. "
            "Previous publication preserved."
        )

        return 1

    # -----------------------------------------------------
    # Score
    # -----------------------------------------------------

    node_by_link = {
        node["link"]: node
        for node in parsed
    }

    ranked = []

    for link, latencies in stable.items():

        node = node_by_link[link]

        score, metrics = calculate_score(
            latencies,
            history.get(
                fingerprint(link),
                {},
            ),
            now,
        )

        item = {
            "link": link,
            "country": node["country"],
            "infrastructure": (
                node["infrastructure"]
            ),
            "endpoint_family": (
                node["endpoint_family"]
            ),
            "normalized": (
                normalized_fingerprint(
                    node
                )
            ),
            "score": score,
            "metrics": metrics,
        }

        ranked.append(item)

    ranked.sort(
        key=lambda item: (
            -item["score"],
            item["metrics"][
                "median_latency_ms"
            ],
        )
    )

    # -----------------------------------------------------
    # Diversity-aware publications
    # -----------------------------------------------------

    best20 = select_diverse(
        ranked,
        20,
    )

    best50 = select_diverse(
        ranked,
        min(
            50,
            len(ranked),
        ),
    )

    best100 = select_diverse(
        ranked,
        min(
            100,
            len(ranked),
        ),
    )

    if len(best20) < 20:

        print(
            "ERROR: diversity selector "
            "could not produce Best20. "
            "Previous publication preserved."
        )

        return 1

    # -----------------------------------------------------
    # Status
    # -----------------------------------------------------

    infrastructure_counts = Counter(
        item["infrastructure"]
        for item in best50
    )

    country_counts = Counter(
        item["country"]
        for item in best50
    )

    endpoint_family_counts = Counter(
        item["endpoint_family"]
        for item in best50
    )

    status = {
        "pipeline_version": CFG.get("pipeline_version", "4.4"),
        "generated_at": now,
        "sources": source_stats,
        "country_policy": {
            "allow": sorted(ALLOWED_COUNTRIES),
            "strict": True,
            "classification": [
                "endpoint_geoip_local_server_country",
                "label_fallback",
            ],
        },
        **stats,
        "published": {
            "best20": len(best20),
            "best50": len(best50),
            "best100": len(best100),
        },
        "diversity": {
            "algorithm": "v4.4-quality-first-diversity",
            "best50_infrastructure_groups": len(
                infrastructure_counts
            ),
            "best50_countries": len(
                country_counts
            ),
            "best50_endpoint_families": len(
                endpoint_family_counts
            ),
            "max_infrastructure_share": (
                max(
                    infrastructure_counts.values()
                )
                if infrastructure_counts
                else 0
            ),
            "max_country_share": (
                max(
                    country_counts.values()
                )
                if country_counts
                else 0
            ),
            "infrastructure_distribution": dict(
                infrastructure_counts
            ),
            "country_distribution": dict(
                country_counts
            ),
            "endpoint_family_distribution": dict(
                endpoint_family_counts
            ),
        },
        "top": [
            {
                "rank": index + 1,
                "score": item["score"],
                "country": item["country"],
                "infrastructure": item[
                    "infrastructure"
                ],
                **item["metrics"],
                "fingerprint": fingerprint(
                    item["link"]
                ),
            }
            for index, item in enumerate(
                best50
            )
        ],
        "test_url": CFG["test_url"],
        "final_attempts": CFG[
            "final_pass"
        ]["attempts"],
        "minimum_final_successes": CFG[
            "final_pass"
        ]["minimum_successes"],
    }

    # -----------------------------------------------------
    # Atomic publication
    # -----------------------------------------------------

    publish_file(
        "best20.txt",
        best20,
        now,
        stats,
    )

    publish_file(
        "best50.txt",
        best50,
        now,
        stats,
    )

    publish_file(
        "best100.txt",
        best100,
        now,
        stats,
    )

    write_status(status)

    print()
    print("======================================")
    print(f"Best50 v{CFG.get('pipeline_version', '4.4')} BUILD SUCCESS")
    print("======================================")
    print(
        f"Candidates:       {stats['candidates']}"
    )
    print(
        f"Parse valid:      {stats['parse_valid']}"
    )
    print(
        f"Exact duplicates:  "
        f"{stats['exact_duplicates_removed']}"
    )
    print(
        f"Structural dupes:  "
        f"{stats['structural_duplicates_removed']}"
    )
    print(
        f"First pass:       "
        f"{stats['first_pass_working']}"
    )
    print(
        f"Final tested:     "
        f"{stats['final_tested']}"
    )
    print(
        f"Final stable:     "
        f"{stats['final_stable']}"
    )
    print(
        f"Best20:           {len(best20)}"
    )
    print(
        f"Best50:           {len(best50)}"
    )
    print(
        f"Best100:          {len(best100)}"
    )
    print(
        f"Best50 infra:     "
        f"{len(infrastructure_counts)}"
    )
    print(
        f"Best50 countries: "
        f"{len(country_counts)}"
    )
    print("======================================")

    return 0


def main() -> int:
    try:
        return asyncio.run(
            main_async()
        )
    except KeyboardInterrupt:
        print(
            "\nInterrupted.",
            file=sys.stderr,
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
