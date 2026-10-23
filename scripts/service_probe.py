#!/usr/bin/env python3
"""Fail-closed, per-candidate application checks for the local subscription.

Only the owned sing-box child opens external connections. It binds every proxy
socket to the requested physical interface and has no direct outbound or TUN.
Every curl process uses authenticated loopback SOCKS with remote destination DNS.
Latency is the median of fresh HTTPS request completion times to generate_204,
including SOCKS, proxy transport, TLS and HTTP, in milliseconds. Service checks are separate
from that latency measurement and every attempted round must pass all services.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import statistics
import tempfile
import time
from urllib.parse import urljoin, urlsplit
import uuid


MAX_CONCURRENT = 4
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HEADERS_BYTES = 64 * 1024
REQUEST_TIMEOUT = 16
STARTUP_TIMEOUT = 5
MAX_LATENCY_MS = 500.0
ALLOWED_OUTBOUND_TYPES = frozenset({"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "socks"})
YOUTUBE_VIDEO = "M7lc1UVf-VE"
SERVICE_URLS = {
    "chatgpt": "https://chatgpt.com/api/auth/providers",
    "youtube": (
        "https://www.youtube.com/oembed?url="
        "https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3D"
        + YOUTUBE_VIDEO + "&format=json"
    ),
    "instagram": "https://www.instagram.com/accounts/login/",
}
ALLOWED_HOSTS = {
    "chatgpt": frozenset({"chatgpt.com", "www.chatgpt.com"}),
    "youtube": frozenset({"youtube.com", "www.youtube.com"}),
    "instagram": frozenset({"instagram.com", "www.instagram.com"}),
    "latency": frozenset({"www.gstatic.com"}),
    "trace": frozenset({"www.cloudflare.com"}),
}
LATENCY_URL = "https://www.gstatic.com/generate_204"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
ANTI_AUTOMATION = (
    b"cf-chl-", b"just a moment", b"verify you are human",
    b"captcha", b"challenge_required", b"login_required",
    b"unusual traffic", b"access denied", b"consent_required",
)


def _safe_url(url: str, service: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname in ALLOWED_HOSTS[service]
            and parsed.port in (None, 443)
            and not parsed.username and not parsed.password
            and not parsed.fragment
            and not re.search(r"/(challenge|checkpoint|consent)(?:/|$)", parsed.path)
        )
    except (TypeError, ValueError, KeyError):
        return False


def validate_response(service: str, response: dict) -> tuple[bool, str]:
    """Validate actual application content; errors and challenges never pass."""
    if response.get("error"):
        return False, str(response["error"])
    code = response.get("status", 0)
    if code == 429:
        return False, "rate-limited-inconclusive"
    if code in (401, 403):
        return False, "access-denied-inconclusive"
    if not _safe_url(response.get("url", ""), service):
        return False, "unexpected-final-url"
    body = response.get("body", b"")
    if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        return False, "invalid-response-size"
    if service == "latency":
        return (True, "ok") if code == 204 and not body else (False, "expected-empty-204")
    if code != 200:
        return False, "http-" + str(code)
    lowered = body.lower()
    # Match visible challenge responses rather than scripts mentioning the word
    # captcha: real Instagram applications may preload captcha code on login.
    if any(marker in lowered for marker in ANTI_AUTOMATION if marker != b"captcha"):
        return False, "challenge-inconclusive"
    content_type = response.get("content_type", "").lower()
    if service in ("chatgpt", "youtube"):
        if "application/json" not in content_type:
            return False, "expected-json"
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            return False, "malformed-json"
        if not isinstance(payload, dict):
            return False, "unexpected-json"
        if service == "chatgpt":
            for name, provider in payload.items():
                if not isinstance(provider, dict):
                    continue
                if not (
                    isinstance(name, str) and name.startswith("openai")
                    and provider.get("id") == name
                    and isinstance(provider.get("name"), str)
                    and bool(provider["name"])
                    and provider.get("type") in ("oauth", "oidc")
                ):
                    continue
                signin, callback = provider.get("signinUrl", ""), provider.get("callbackUrl", "")
                if (
                    _safe_url(signin, "chatgpt") and _safe_url(callback, "chatgpt")
                    and urlsplit(signin).path == "/api/auth/signin/" + name
                    and urlsplit(callback).path == "/api/auth/callback/" + name
                ):
                    return True, "ok"
            return False, "unexpected-auth-providers"
        iframe = payload.get("html", "")
        iframe_match = re.search(r'<iframe\b[^>]*\bsrc=["\']([^"\']+)["\']', iframe) if isinstance(iframe, str) else None
        try:
            embed = urlsplit(iframe_match.group(1)) if iframe_match else None
            valid_port = embed is not None and embed.port in (None, 443)
        except ValueError:
            return False, "unexpected-oembed"
        valid = (
            payload.get("provider_name") == "YouTube"
            and payload.get("type") == "video"
            and isinstance(payload.get("title"), str) and bool(payload["title"].strip())
            and embed is not None and embed.scheme == "https"
            and embed.hostname in ALLOWED_HOSTS["youtube"]
            and valid_port
            and embed.path == "/embed/" + YOUTUBE_VIDEO
            and not embed.username and not embed.password
        )
        return (True, "ok") if valid else (False, "unexpected-oembed")
    if service == "instagram":
        if "text/html" not in content_type or len(body) < 1024:
            return False, "expected-instagram-html"
        # Require both an actual Instagram web application module and Instagram
        # application metadata. A generic login, captive portal, or branded
        # intermediary page cannot qualify merely by mentioning Instagram.
        app = any(marker in body for marker in (b"PolarisLogin", b"IGDLogin", b"InstagramLogin"))
        metadata = bool(re.search(
            rb'<(?:link|meta)\b[^>]*(?:href|content)=["\']https://(?:www\.)?instagram\.com/',
            body, re.IGNORECASE,
        ))
        scripts = b"static.cdninstagram.com" in body or b"instagram.com/rsrc.php/" in body
        if app and metadata and scripts:
            return True, "ok"
        return False, "unexpected-instagram-application"
    if service == "trace":
        trace = parse_exit_trace(body)
        return (True, "ok") if trace else (False, "unexpected-exit-trace")
    return False, "unknown-service"


def parse_exit_trace(body: bytes) -> dict | None:
    try:
        fields = dict(line.split("=", 1) for line in body.decode("ascii").splitlines() if "=" in line)
        address = ipaddress.ip_address(fields.get("ip", ""))
        location = fields.get("loc", "")
        if not address.is_global or not re.fullmatch(r"[A-Z]{2}", location):
            return None
        return {"ip": str(address), "loc": location}
    except (ValueError, UnicodeError):
        return None


async def _resolve_public_server(host: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(host)
        addresses = [address]
    except ValueError:
        resolved = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=5,
        )
        addresses = [ipaddress.ip_address(item[4][0]) for item in resolved]
    public = sorted({str(address) for address in addresses if address.is_global and not address.is_multicast})
    # Mixed private/public DNS is rejected, rather than letting resolution order
    # select a private endpoint. The selected public address is pinned in config.
    if not public or any(not address.is_global or address.is_multicast for address in addresses):
        raise ValueError("non-public-server")
    return public[0]


def make_config(build, node: dict, server_ip: str, interface: str, port: int, username: str, password: str) -> dict:
    outbound = build.vless_to_singbox(node, tag="candidate")
    if outbound.get("type") not in ALLOWED_OUTBOUND_TYPES:
        raise ValueError("invalid-outbound")
    if outbound["type"] in {"vless", "vmess"}:
        uuid.UUID(outbound["uuid"])
    outbound["server"] = server_ip
    outbound["bind_interface"] = interface
    # Preserve the name before pinning DNS. This also covers converters without
    # an explicit SNI fallback and avoids certificate validation against the IP.
    if outbound.get("tls", {}).get("enabled"):
        outbound["tls"]["server_name"] = node.get("sni") or node["server"]
        if outbound["tls"].get("insecure"):
            raise ValueError("insecure-tls")
    return {
        "log": {"disabled": True},
        "inbounds": [{"type": "socks", "tag": "probe", "listen": "127.0.0.1", "listen_port": port,
                      "users": [{"username": username, "password": password}]}],
        "outbounds": [outbound],
        "route": {"default_interface": interface, "final": "candidate"},
    }


async def _wait_authenticated(port: int, username: str, password: str, process) -> None:
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.returncode is not None:
            raise RuntimeError("proxy-start-failed")
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), .3)
            writer.write(b"\x05\x01\x02")
            await writer.drain()
            if await asyncio.wait_for(reader.readexactly(2), .3) != b"\x05\x02":
                raise RuntimeError("proxy-authentication-required")
            user, password_bytes = username.encode(), password.encode()
            writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password_bytes)]) + password_bytes)
            await writer.drain()
            if await asyncio.wait_for(reader.readexactly(2), .3) != b"\x01\x00":
                raise RuntimeError("proxy-authentication-failed")
            return
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            await asyncio.sleep(.05)
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()
    raise RuntimeError("proxy-start-timeout")


async def _stop(build, process) -> None:
    await build._stop_owned_probe_process(process)


def _curl_command(url: str, port: int, username: str, password: str) -> list[str]:
    return [
        shutil.which("curl") or "curl", "--disable", "--silent", "--show-error",
        "--proxy", "socks5h://127.0.0.1:" + str(port), "--proxy-user", username + ":" + password,
        "--socks5-basic", "--noproxy", "", "--proto", "=https", "--proto-redir", "=https",
        "--connect-timeout", "5", "--max-time", str(REQUEST_TIMEOUT),
        "--max-filesize", str(MAX_RESPONSE_BYTES), "--compressed",
        "--user-agent", "BestLocal-Functional-Validator/1.0",
        "--header", "Accept: application/json,text/html;q=0.9,*/*;q=0.1",
        "--write-out", "\nBESTLOCAL_TIME_TOTAL:%{time_total}",
        "--dump-header", "-", "--output", "-", "--url", url,
    ]


async def _http_once(build, url: str, port: int, username: str, password: str) -> dict:
    """Read a bounded HTTP response; never follow a redirect in curl itself."""
    command = _curl_command(url, port, username, password)
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return {"error": "request-process-failed", "url": url}
    build._register_owned_probe_process(process)
    output = bytearray()
    try:
        async def read_response():
            while True:
                chunk = await process.stdout.read(64 * 1024)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_RESPONSE_BYTES + MAX_HEADERS_BYTES:
                    raise ValueError("response-too-large")
            await process.wait()
        await asyncio.wait_for(read_response(), REQUEST_TIMEOUT + 2)
        if process.returncode != 0:
            reason = {5: "proxy-name-resolution-failed", 6: "destination-name-resolution-failed",
                      7: "loopback-proxy-unavailable", 28: "proxy-request-timeout",
                      35: "destination-tls-failed", 51: "destination-certificate-invalid",
                      60: "destination-certificate-invalid", 56: "proxy-receive-failed",
                      63: "response-too-large", 97: "socks-connection-failed"}.get(process.returncode, "proxy-request-failed")
            return {"error": reason, "curl_exit": process.returncode, "url": url}
        data, marker, elapsed_raw = bytes(output).rpartition(b"\nBESTLOCAL_TIME_TOTAL:")
        if not marker:
            return {"error": "missing-request-timing", "url": url}
        elapsed = float(elapsed_raw) * 1000
        # curl -D - emits any HTTP/1.1 100/103 intermediate headers ahead of
        # the real response. Accept only bounded well-formed header blocks.
        while True:
            header, separator, body = data.partition(b"\r\n\r\n")
            if not separator or len(header) > MAX_HEADERS_BYTES:
                return {"error": "malformed-http-headers", "url": url}
            match = re.fullmatch(rb"HTTP/(?:1\.[01]|2|3) (\d{3})(?: .*)?", header.split(b"\r\n", 1)[0])
            if not match:
                return {"error": "malformed-http-status", "url": url}
            code = int(match.group(1))
            if code < 200:
                data = body
                continue
            headers = {}
            for line in header.split(b"\r\n")[1:]:
                name, colon, value = line.partition(b":")
                if colon:
                    headers[name.decode("ascii", "ignore").lower()] = value.decode("latin1").strip()
            return {"status": code, "url": url, "body": body, "content_type": headers.get("content-type", ""),
                    "location": headers.get("location", ""), "latency_ms": elapsed}
    except asyncio.TimeoutError:
        return {"error": "proxy-request-timeout", "url": url}
    except ValueError:
        return {"error": "response-too-large", "url": url}
    finally:
        await _stop(build, process)


async def _request(build, service: str, url: str, port: int, username: str, password: str) -> dict:
    for hop in range(4):
        if not _safe_url(url, service):
            return {"error": "unexpected-redirect", "url": url}
        response = await _http_once(build, url, port, username, password)
        if response.get("status") not in (301, 302, 303, 307, 308):
            return response
        if hop == 3 or not response.get("location"):
            return {"error": "redirect-limit", "url": url}
        url = urljoin(url, response["location"])
    return {"error": "redirect-limit", "url": url}


def summarize_report(report: dict, rounds: int) -> dict:
    samples = report["latency_samples_ms"]
    valid = len(samples) == rounds and all(isinstance(value, (int, float)) and math.isfinite(value) and value >= 0 for value in samples)
    if valid:
        report["median_ms"] = statistics.median(samples)
        report["p95_ms"] = sorted(samples)[max(0, math.ceil(.95 * len(samples)) - 1)]
    all_services = all(result["passed"] == rounds and result["attempts"] == rounds for result in report["services"].values())
    if not all_services:
        report["rejection_reasons"].append("service-requirements-failed")
    if not valid:
        report["rejection_reasons"].append("insufficient-latency-samples")
    elif not report["median_ms"] < MAX_LATENCY_MS:
        report["rejection_reasons"].append("latency-not-below-500ms")
    report["qualified"] = all_services and valid and report["median_ms"] < MAX_LATENCY_MS and not report["rejection_reasons"]
    return report


async def _validate_one(build, link: str, rounds: int, interface: str) -> dict:
    started = time.monotonic()
    report = {
        "id": hashlib.sha256(link.encode()).hexdigest()[:16], "qualified": False,
        "services": {name: {"passed": 0, "attempts": 0, "reasons": []} for name in SERVICE_URLS},
        "latency_samples_ms": [], "median_ms": None, "p95_ms": None, "rejection_reasons": [],
        "validated_at": datetime.now(timezone.utc).isoformat(), "exit_trace": None,
    }
    process = None
    try:
        if len(link) > 16384 or any(ord(char) < 32 for char in link):
            raise ValueError("invalid-config")
        node = build.parse_vless(link)
        server_ip = await _resolve_public_server(node["server"], node["port"])
        username, password = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        # Reserve a free ephemeral port. Authentication prevents confusing a
        # foreign process winning the bind race with this candidate's proxy.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        config = make_config(build, node, server_ip, interface, port, username, password)
        with tempfile.TemporaryDirectory(prefix="bestlocal-service-") as directory:
            path = Path(directory) / "config.json"
            with path.open("x", encoding="utf-8") as stream:
                os.chmod(path, 0o600)
                json.dump(config, stream)
            process = await asyncio.create_subprocess_exec(
                str(build.SING_BOX), "run", "-c", str(path),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            build._register_owned_probe_process(process)
            try:
                await _wait_authenticated(port, username, password, process)
                for _ in range(rounds):
                    # Deliberately finish all three checks in a failed round so
                    # diagnostics never imply an unattempted service succeeded.
                    results = await asyncio.gather(*(
                        _request(build, name, url, port, username, password)
                        for name, url in SERVICE_URLS.items()
                    ), _request(build, "latency", LATENCY_URL, port, username, password), return_exceptions=True)
                    results = [result if isinstance(result, dict) else {"error": "proxy-request-failed"} for result in results]
                    failed = False
                    for name, response in zip(SERVICE_URLS, results[:3]):
                        passed, reason = validate_response(name, response)
                        result = report["services"][name]
                        result["attempts"] += 1
                        result["passed"] += int(passed)
                        result["reasons"].append(reason)
                        failed |= not passed
                    latency_ok, reason = validate_response("latency", results[3])
                    sample = results[3].get("latency_ms")
                    if latency_ok and isinstance(sample, (float, int)) and math.isfinite(sample) and sample >= 0:
                        report["latency_samples_ms"].append(sample)
                    else:
                        report["rejection_reasons"].append("latency-" + (reason if not latency_ok else "invalid-timing"))
                        failed = True
                    if process.returncode is not None:
                        report["rejection_reasons"].append("proxy-exited")
                        failed = True
                    if failed:
                        break
                summarize_report(report, rounds)
                if report["qualified"]:
                    trace = await _request(build, "trace", TRACE_URL, port, username, password)
                    trace_ok, reason = validate_response("trace", trace)
                    if trace_ok:
                        report["exit_trace"] = parse_exit_trace(trace["body"])
                    else:
                        report["exit_trace_reason"] = reason
            finally:
                await _stop(build, process)
                process = None
    except asyncio.CancelledError:
        raise
    except (ValueError, KeyError, TypeError):
        report["qualified"] = False
        report["rejection_reasons"].append("invalid-or-unsafe-config")
    except (OSError, RuntimeError, asyncio.TimeoutError):
        report["qualified"] = False
        report["rejection_reasons"].append("proxy-start-or-network-failure")
    finally:
        if process is not None:
            await _stop(build, process)
        report["duration_s"] = round(time.monotonic() - started, 3)
    return report


async def validate_candidates(build, links: list[str], rounds: int = 5, interface: str = "en0") -> dict[str, dict]:
    """Validate independently, with at most four candidates / sixteen requests.

    The 3..5 round bounds are policy: an accidental flag cannot turn a single
    lucky response into authoritative qualification. No system network API or
    existing VPN process is inspected or modified here.
    """
    if not isinstance(rounds, int) or not 3 <= rounds <= 5:
        raise ValueError("service validation requires 3 to 5 rounds")
    if not re.fullmatch(r"en[0-9]+", interface):
        raise ValueError("service validation requires a physical en interface")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    async def one(link):
        async with semaphore:
            return link, await _validate_one(build, link, rounds, interface)
    tasks = [asyncio.create_task(one(link)) for link in dict.fromkeys(links)]
    try:
        return dict(await asyncio.gather(*tasks))
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
