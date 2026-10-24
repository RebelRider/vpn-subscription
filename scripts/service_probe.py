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
from collections import Counter
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
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
import sys
import time
import uuid
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from owned_temporary import temporary_directory


MAX_CONCURRENT = 4
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_HEADERS_BYTES = 64 * 1024
REQUEST_TIMEOUT = 16
STARTUP_TIMEOUT = 5
MAX_LATENCY_MS = 500.0
MAX_ERROR_BYTES = 64 * 1024
MAX_CANDIDATE_SECONDS = 180
BROWSER_REASON_CODES = frozenset({
    "browser-application-proof-missing", "browser-api-proof-missing", "browser-busy-inconclusive",
    "browser-check-unavailable", "browser-deadline", "browser-invalid-evidence",
    "browser-isolation-test-failed", "browser-network-isolation-unavailable", "browser-process-failed",
    "browser-proxy-authentication-missing", "browser-runtime-failed", "browser-runtime-unavailable",
    "browser-navigation-failed", "browser-proxy-failed", "browser-requirements-inconclusive",
    "browser-timeout-inconclusive", "browser-tls-failed", "cloudflare-challenge-inconclusive",
    "anti-automation-inconclusive", "access-denied-inconclusive", "geographic-restriction",
    "rate-limited-inconclusive",
    "browser-composer-not-actionable-inconclusive", "browser-document-proof-missing-inconclusive",
    "browser-document-changed-inconclusive", "browser-document-http-error-inconclusive",
    "authentication-required-inconclusive", "browser-visible-application-error-inconclusive",
})
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
CF_CHALLENGE_MARKERS = (b"cf-chl-", b"/cdn-cgi/challenge-platform/", b"just a moment", b"verify you are human")
GEO_RESTRICTION_MARKERS = (
    b"unsupported_country_region_territory", b"country_not_supported",
    b"not available in your country", b"not available in your region",
    b"unsupported country", b"country, region, or territory is not supported",
)


class _VisibleText(HTMLParser):
    """Bounded HTML text, excluding inert bundles and explicitly hidden nodes."""
    VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.parts = []
        self.size = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        style = re.sub(r"\s+", "", values.get("style") or "").lower()
        hidden = ((self.stack and self.stack[-1][1]) or tag in {"script", "style", "template", "noscript"}
                  or "hidden" in values or (values.get("aria-hidden") or "").lower() == "true"
                  or "display:none" in style or "visibility:hidden" in style)
        if tag not in self.VOID:
            if len(self.stack) >= 256:
                raise ValueError("HTML nesting exceeds probe limit")
            self.stack.append((tag, bool(hidden)))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if not (self.stack and self.stack[-1][1]) and self.size < 65536:
            value = data[:65536 - self.size]
            self.parts.append(value)
            self.size += len(value)


def _restriction_text(response: dict) -> bytes:
    body = response.get("body", b"")
    if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        return b""
    content_type = response.get("content_type", "")
    if isinstance(content_type, str) and "application/json" in content_type.lower():
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError, RecursionError):
            payload = None
        if isinstance(payload, dict):
            parts = []
            # Error values are evidence; arbitrary titles, source strings and
            # translation dictionaries are not an active service restriction.
            for key in ("error", "error_description", "error_type", "message", "detail", "code"):
                value = payload.get(key)
                if isinstance(value, str):
                    parts.append(value[:4096])
                elif isinstance(value, dict):
                    parts.extend(value[name][:4096] for name in ("message", "code", "type") if isinstance(value.get(name), str))
            parts.extend(key for key in ("challenge_required", "login_required", "consent_required") if payload.get(key) is True)
            return " ".join(parts).lower().encode()
    parser = _VisibleText()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, RecursionError):
        return b""
    return " ".join(parser.parts).lower().encode()


def response_restrictions(response: dict) -> tuple[bool, bool]:
    """Return only explicit challenge/geography evidence, never infer it from 403."""
    body = response.get("body", b"")
    if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        body = b""
    lowered = _restriction_text(response)
    challenge = response.get("cf_mitigated") == "challenge" or any(marker in lowered for marker in CF_CHALLENGE_MARKERS)
    # A translated/static app bundle may mention unsupported countries without
    # restricting this request. Require an actual error response or JSON error.
    geographic = any(marker in lowered for marker in GEO_RESTRICTION_MARKERS) and (
        response.get("status") in (400, 401, 403, 451)
        or (isinstance(response.get("content_type"), str) and "application/json" in response["content_type"].lower()
            and b'"error"' in body.lower())
    )
    return bool(challenge), bool(geographic)


def classify_error(data: bytes) -> str:
    """Reduce untrusted engine/curl messages to an allowlisted, credential-free enum."""
    text = data[:8192].lower()
    groups = (
        ("dns-failed", (b"no such host", b"name resolution", b"resolve host", b"dns exchange", b"lookup ")),
        ("routing-no-route", (b"no route to host", b"network is unreachable", b"network unreachable")),
        ("tls-certificate-invalid", (b"certificate verify", b"certificate is not valid", b"x509:", b"unknown certificate")),
        ("protocol-authentication-failed", (b"authentication failed", b"invalid password", b"invalid user", b"unknown user", b"authentication failure")),
        ("configuration-invalid", (b"decode config", b"parse config", b"unknown field", b"invalid configuration", b"initialize outbound")),
        ("connection-refused", (b"connection refused", b"actively refused")),
        ("timeout", (b"timed out", b"timeout", b"deadline exceeded")),
        ("tls-handshake-failed", (b"tls:", b"tls handshake", b"ssl connect", b"ssl error")),
        ("protocol-handshake-failed", (b"invalid response", b"invalid header", b"bad response", b"reality verification", b"handshake failed")),
        ("connection-reset", (b"connection reset", b"broken pipe", b"unexpected eof")),
        ("socks-connection-failed", (b"socks5", b"socks connection")),
        ("connection-eof", (b" eof", b": eof")),
    )
    return next((name for name, markers in groups if any(marker in text for marker in markers)), "unclassified-error")


async def drain_error_classes(reader, counters: Counter) -> None:
    """Drain child stderr without retaining raw output, with bounded parsing/memory."""
    if reader is None:
        return
    pending = bytearray()
    consumed = 0
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        remaining = max(0, MAX_ERROR_BYTES - consumed)
        if remaining:
            pending.extend(chunk[:remaining])
            consumed += min(remaining, len(chunk))
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending[:] = rest
                if line.strip():
                    key = classify_error(bytes(line))
                    counters[key] = min(999, counters[key] + 1)
            if len(pending) > 8192:
                key = classify_error(bytes(pending))
                counters[key] = min(999, counters[key] + 1)
                pending.clear()
        if len(chunk) > remaining:
            counters["diagnostic-output-truncated"] = 1
    if pending.strip():
        key = classify_error(bytes(pending))
        counters[key] = min(999, counters[key] + 1)


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
    if not _safe_url(response.get("url", ""), service):
        return False, "unexpected-final-url"
    body = response.get("body", b"")
    if not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        return False, "invalid-response-size"
    challenge, geographic = response_restrictions(response)
    if geographic:
        return False, "geographic-restriction"
    if challenge:
        return False, "cloudflare-challenge-inconclusive"
    if code == 429:
        return False, "rate-limited-inconclusive"
    if code == 401:
        return False, "authentication-required-inconclusive"
    if code == 403:
        return False, "access-denied-inconclusive"
    if service == "latency":
        if urlsplit(response["url"]).path != "/generate_204":
            return False, "unexpected-latency-path"
        return (True, "ok") if code == 204 and not body else (False, "expected-empty-204")
    if service == "chatgpt" and code in (404, 410):
        return False, "chatgpt-endpoint-unavailable-inconclusive"
    if code != 200:
        return False, "http-" + str(code)
    lowered = _restriction_text(response)
    if any(marker in lowered for marker in ANTI_AUTOMATION if marker != b"captcha"):
        return False, "challenge-inconclusive"
    content_type = response.get("content_type", "")
    if not isinstance(content_type, str):
        return False, "invalid-response-content-type"
    content_type = content_type.lower()
    path = urlsplit(response["url"]).path.rstrip("/")
    paths = {"chatgpt": {"/api/auth/providers"}, "youtube": {"/oembed"},
             "instagram": {"", "/accounts/login"}, "trace": {"/cdn-cgi/trace"}}
    if service in paths and path not in paths[service]:
        return False, "unexpected-application-path-inconclusive"
    if service in ("chatgpt", "youtube"):
        if "application/json" not in content_type:
            return False, "chatgpt-endpoint-unexpected-content-inconclusive" if service == "chatgpt" else "expected-json"
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            return False, "chatgpt-endpoint-malformed-json-inconclusive" if service == "chatgpt" else "malformed-json"
        if not isinstance(payload, dict):
            return False, "chatgpt-endpoint-unexpected-json-inconclusive" if service == "chatgpt" else "unexpected-json"
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
            # This endpoint is not a stable public application contract: a
            # functional guest browser can receive HTTP 200 with an empty {}.
            # Only a separate actual browser application proof may resolve it.
            return False, "chatgpt-auth-method-inconclusive"
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


def service_evidence(service: str, response: dict) -> dict:
    passed, reason = validate_response(service, response)
    challenge, geographic = response_restrictions(response)
    status, exit_code = response.get("status"), response.get("curl_exit")
    return {
        "outcome": "pass" if passed else ("inconclusive" if reason.endswith("inconclusive") else "fail"),
        "reason": reason,
        "http_reason": reason,
        "http_status": status if type(status) is int and 100 <= status <= 599 else None,
        "curl_exit": exit_code if type(exit_code) is int and 0 <= exit_code <= 255 else None,
        "cf_challenge": challenge, "geo_restricted": geographic,
        "transport_errors": dict(response.get("transport_errors", {})),
    }


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


async def _resolve_public_servers(host: str, port: int) -> list[str]:
    try:
        address = ipaddress.ip_address(host)
        addresses = [address]
    except ValueError:
        resolved = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=5,
        )
        addresses = [ipaddress.ip_address(item[4][0]) for item in resolved]
    public = sorted({str(address) for address in addresses if address.is_global and not address.is_multicast},
                    key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))
    # Mixed private/public DNS is rejected, rather than letting resolution order
    # select a private endpoint. The selected public address is pinned in config.
    if not public or any(not address.is_global or address.is_multicast for address in addresses):
        raise ValueError("non-public-server")
    return public


async def _resolve_public_server(host: str, port: int) -> str:
    # Kept as a compatibility entry point; callers can explicitly retry the
    # complete validated address set without allowing private DNS fallback.
    return (await _resolve_public_servers(host, port))[0]


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
        "log": {"level": "error", "timestamp": False},
        "inbounds": [{"type": "mixed", "tag": "probe", "listen": "127.0.0.1", "listen_port": port,
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
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        return {"error": "request-process-failed", "url": url}
    build._register_owned_probe_process(process)
    output = bytearray()
    error_classes = Counter()
    error_task = asyncio.create_task(drain_error_classes(getattr(process, "stderr", None), error_classes))
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
        await asyncio.wait_for(asyncio.gather(read_response(), error_task), REQUEST_TIMEOUT + 2)
        if process.returncode != 0:
            reason = {5: "proxy-name-resolution-failed", 6: "destination-name-resolution-failed",
                      7: "loopback-proxy-unavailable", 28: "proxy-request-timeout",
                      35: "destination-tls-failed", 51: "destination-certificate-invalid",
                      60: "destination-certificate-invalid", 56: "proxy-receive-failed",
                      63: "response-too-large", 97: "socks-connection-failed"}.get(process.returncode, "proxy-request-failed")
            return {"error": reason, "curl_exit": process.returncode, "url": url,
                    "transport_errors": dict(error_classes)}
        data, marker, elapsed_raw = bytes(output).rpartition(b"\nBESTLOCAL_TIME_TOTAL:")
        if not marker:
            return {"error": "missing-request-timing", "url": url}
        elapsed = float(elapsed_raw) * 1000
        if not math.isfinite(elapsed) or elapsed < 0:
            return {"error": "invalid-request-timing", "url": url, "curl_exit": 0}
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
                    "location": headers.get("location", ""), "latency_ms": elapsed,
                    "curl_exit": 0, "cf_mitigated": "challenge" if headers.get("cf-mitigated", "").lower() == "challenge" else "",
                    "transport_errors": dict(error_classes)}
    except asyncio.TimeoutError:
        return {"error": "proxy-request-timeout", "url": url}
    except ValueError:
        return {"error": "response-too-large", "url": url}
    finally:
        await _stop(build, process)
        if not error_task.done():
            error_task.cancel()
        await asyncio.gather(error_task, return_exceptions=True)


async def _request(build, service: str, url: str, port: int, username: str, password: str) -> dict:
    for hop in range(4):
        if not _safe_url(url, service):
            return {"error": "unexpected-redirect", "url": url}
        response = await _http_once(build, url, port, username, password)
        if response.get("status") not in (301, 302, 303, 307, 308):
            return response
        if hop == 3 or not response.get("location"):
            return {"error": "redirect-limit", "url": url}
        destination = urljoin(url, response["location"])
        if not _safe_url(destination, service):
            # A real HTTPS service redirect is application/endpoint ambiguity,
            # not an endpoint transport failure. Never follow an unsafe target.
            return {**response, "error": "service-redirect-restriction-inconclusive"}
        url = destination
    return {"error": "redirect-limit", "url": url}


def summarize_report(report: dict, rounds: int) -> dict:
    samples = report["latency_samples_ms"]
    valid = len(samples) == rounds and all(type(value) in (int, float) and math.isfinite(value) and value >= 0 for value in samples)
    if valid:
        report["median_ms"] = statistics.median(samples)
        report["p95_ms"] = sorted(samples)[max(0, math.ceil(.95 * len(samples)) - 1)]
    services = report.get("services", {})
    all_services = (isinstance(services, dict) and set(services) == set(SERVICE_URLS)
                    and all(isinstance(result, dict) and type(result.get("passed")) is int
                            and type(result.get("attempts")) is int
                            and result["passed"] == rounds and result["attempts"] == rounds
                            for result in services.values()))
    if not all_services:
        report["rejection_reasons"].append("service-requirements-failed")
    if not valid:
        report["rejection_reasons"].append("insufficient-latency-samples")
    elif not report["median_ms"] < MAX_LATENCY_MS:
        report["rejection_reasons"].append("latency-not-below-500ms")
    report["qualified"] = all_services and valid and report["median_ms"] < MAX_LATENCY_MS and not report["rejection_reasons"]
    return report


async def check_chatgpt(build, port: int, username: str, password: str, rounds: int) -> dict:
    """Lazy browser adapter: missing dependencies and browser errors remain inconclusive."""
    try:
        from browser_probe import check_chatgpt as browser_check
        result = await browser_check(build, port, username, password, rounds=rounds, control=False)
        return result if isinstance(result, dict) else {"qualified": False, "reason": "browser-invalid-result"}
    except asyncio.CancelledError:
        raise
    except Exception:
        # A browser exception may contain a proxy URL, page response, or local
        # credentials. Only the closed enum is retained in operational logs.
        return {"qualified": False, "reason": "browser-check-unavailable"}


def fresh_browser_rounds(result: dict, rounds: int, port: int | None = None) -> list[dict] | None:
    if not isinstance(result, dict) or result.get("qualified") is not True:
        return None
    if port is not None and (result.get("control") is not False or result.get("proxy_port") != port):
        return None
    values = result.get("rounds")
    if not isinstance(values, list) or len(values) != rounds:
        return None
    now = datetime.now(timezone.utc)
    clean = []
    for item in values:
        if (not isinstance(item, dict) or item.get("passed") is not True or item.get("reason") != "ok"
                or type(item.get("http_status")) is not int or item["http_status"] != 200
                or any(item.get(field) is not True for field in ("composer", "application_json", "actionable", "restriction_free"))):
            return None
        try:
            value = item["checked_at"]
            if not isinstance(value, str) or len(value) > 80:
                return None
            checked = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if checked.tzinfo is None or not 0 <= (now - checked).total_seconds() <= 180:
                return None
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        clean.append({"passed": True, "checked_at": checked.isoformat(), "actionable": True,
                      "restriction_free": True, "composer": True, "application_json": True, "http_status": 200})
    return clean


def browser_diagnostic(result: dict, proof: list[dict] | None) -> dict:
    """Expose only bounded enums and booleans from the first failed browser round."""
    diagnostic = {"attempted": True, "qualified": proof is not None, "rounds": len(proof) if proof else 0,
                  "reason": "browser-functional-proof" if proof else "browser-proof-inconclusive"}
    if proof is not None or not isinstance(result, dict):
        return diagnostic
    rounds = result.get("rounds", [])
    failed = next((item for item in rounds[:5] if isinstance(item, dict)
                   and (item.get("passed") is not True or item.get("reason") != "ok")), None) if isinstance(rounds, list) else None
    reason = failed.get("reason") if failed else result.get("reason")
    if isinstance(reason, str) and reason in BROWSER_REASON_CODES:
        diagnostic["reason"] = reason
    if isinstance(rounds, list):
        diagnostic["attempted_rounds"] = min(5, len(rounds))
        diagnostic["passed_rounds"] = sum(isinstance(item, dict) and item.get("passed") is True for item in rounds[:5])
    if failed:
        status = failed.get("http_status")
        diagnostic["first_failed_http_status"] = status if type(status) is int and 100 <= status <= 599 else None
        for field in ("composer", "application_json"):
            value = failed.get(field)
            diagnostic["first_failed_" + field] = value if type(value) is bool else None
    return diagnostic


def empty_report(link: str) -> dict:
    return {
        "id": hashlib.sha256(link.encode()).hexdigest()[:16], "qualified": False,
        "services": {name: {"passed": 0, "attempts": 0, "reasons": [], "evidence": []} for name in SERVICE_URLS},
        "latency_samples_ms": [], "median_ms": None, "p95_ms": None, "rejection_reasons": [],
        "validated_at": datetime.now(timezone.utc).isoformat(), "exit_trace": None,
        "engine_errors": {}, "latency_checks": [],
    }


async def _validate_address(build, link: str, rounds: int, interface: str, server_ip: str,
                            progress: dict | None = None) -> dict:
    """One completely owned proxy process and one pinned, already-validated address."""
    started = time.monotonic()
    report = empty_report(link)
    if progress is not None:
        progress["report"] = report
    process = None
    engine_errors = Counter()
    engine_error_task = None
    try:
        if len(link) > 16384 or any(ord(char) < 32 for char in link):
            raise ValueError("invalid-config")
        node = build.parse_vless(link)
        report["protocol"] = node.get("protocol", "vless")
        address = ipaddress.ip_address(server_ip)
        if not address.is_global or address.is_multicast:
            raise ValueError("non-public-server")
        username, password = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
        # Reserve a free ephemeral port. Authentication prevents confusing a
        # foreign process winning the bind race with this candidate's proxy.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        config = make_config(build, node, server_ip, interface, port, username, password)
        with temporary_directory(prefix="bestlocal-service-") as directory:
            path = Path(directory) / "config.json"
            with path.open("x", encoding="utf-8") as stream:
                os.chmod(path, 0o600)
                json.dump(config, stream)
            process = await asyncio.create_subprocess_exec(
                str(build.SING_BOX), "run", "-c", str(path),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            build._register_owned_probe_process(process)
            engine_error_task = asyncio.create_task(drain_error_classes(getattr(process, "stderr", None), engine_errors))
            try:
                await _wait_authenticated(port, username, password, process)
                browser_attempted = False
                browser_result = None
                for round_index in range(rounds):
                    # Deliberately finish all three checks in a failed round so
                    # diagnostics never imply an unattempted service succeeded.
                    results = await asyncio.gather(*(
                        _request(build, name, url, port, username, password)
                        for name, url in SERVICE_URLS.items()
                    ), _request(build, "latency", LATENCY_URL, port, username, password), return_exceptions=True)
                    results = [result if isinstance(result, dict) else {"error": "proxy-request-failed"} for result in results]
                    evidence = {name: service_evidence(name, response) for name, response in zip(SERVICE_URLS, results[:3])}
                    latency_ok, reason = validate_response("latency", results[3])
                    sample = results[3].get("latency_ms")
                    valid_sample = latency_ok and type(sample) in (float, int) and math.isfinite(sample) and sample >= 0
                    # Preserve completed HTTP evidence before waiting for the
                    # serialized browser. A browser queue deadline must never
                    # erase evidence and become a purported transport failure.
                    for name, item in evidence.items():
                        current = report["services"][name]
                        current["attempts"] += 1
                        current["passed"] += int(item["outcome"] == "pass")
                        current["reasons"].append(item["reason"])
                        current["evidence"].append(item)
                    report["latency_checks"].append(service_evidence("latency", results[3]))
                    if valid_sample:
                        report["latency_samples_ms"].append(sample)
                    chatgpt = evidence["chatgpt"]
                    eligible_browser = (
                        chatgpt["outcome"] == "inconclusive"
                        and chatgpt["http_status"] != 429
                        and chatgpt["reason"] != "rate-limited-inconclusive"
                        and not chatgpt["geo_restricted"]
                        and all(evidence[name]["outcome"] == "pass" for name in ("youtube", "instagram"))
                        and valid_sample
                    )
                    if eligible_browser:
                        if not browser_attempted:
                            browser_attempted = True
                            report["browser_check"] = {"attempted": True, "qualified": False, "rounds": 0,
                                                       "reason": "browser-queue-or-execution-pending"}
                            browser_result = await check_chatgpt(build, port, username, password, rounds)
                            proof = fresh_browser_rounds(browser_result, rounds, port)
                            report["browser_check"] = browser_diagnostic(browser_result, proof)
                        proof = fresh_browser_rounds(browser_result, rounds, port)
                        if proof is not None:
                            chatgpt.update(http_outcome=chatgpt["outcome"], http_reason=chatgpt["reason"],
                                           outcome="pass", reason="browser-functional-access",
                                           browser=proof[round_index])
                            report["services"]["chatgpt"]["passed"] += 1
                            report["services"]["chatgpt"]["reasons"][-1] = chatgpt["reason"]
                    failed = any(item["outcome"] != "pass" for item in evidence.values())
                    if not valid_sample:
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
                if engine_error_task is not None:
                    try:
                        await asyncio.wait_for(asyncio.shield(engine_error_task), 1)
                    except asyncio.TimeoutError:
                        engine_error_task.cancel()
                        await asyncio.gather(engine_error_task, return_exceptions=True)
                    except asyncio.CancelledError:
                        engine_error_task.cancel()
                        await asyncio.gather(engine_error_task, return_exceptions=True)
                        raise
                    engine_error_task = None
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
        if engine_error_task is not None:
            engine_error_task.cancel()
            await asyncio.gather(engine_error_task, return_exceptions=True)
        report["engine_errors"] = dict(engine_errors)
        report["duration_s"] = round(time.monotonic() - started, 3)
    return report


def has_https_response(report: dict) -> bool:
    """HTTP restrictions are successful transport evidence and never rotate IPs."""
    if report.get("latency_samples_ms"):
        return True
    evidence = list(report.get("latency_checks", []))
    for item in report.get("services", {}).values():
        if item.get("passed", 0):
            return True
        evidence.extend(item.get("evidence", []))
    return any(type(item.get("http_status")) is int and 100 <= item["http_status"] <= 599
               for item in evidence if isinstance(item, dict))


async def _validate_one(build, link: str, rounds: int, interface: str) -> dict:
    """Try at most two public addresses, only after a complete transport failure."""
    started = time.monotonic()
    report = empty_report(link)
    attempts = []
    progress = {}
    try:
        if len(link) > 16384 or any(ord(char) < 32 for char in link):
            raise ValueError("invalid-config")
        node = build.parse_vless(link)
        report["protocol"] = node.get("protocol", "vless")
        addresses = await _resolve_public_servers(node["server"], node["port"])
        if not addresses:
            raise ValueError("non-public-server")
        for index, address in enumerate(addresses[:2], 1):
            remaining = MAX_CANDIDATE_SECONDS - (time.monotonic() - started)
            if remaining <= 0:
                raise asyncio.TimeoutError
            attempt = {"attempt": index, "address_id": hashlib.sha256(address.encode()).hexdigest()[:16],
                       "https_response": False, "engine_errors": {}, "rejection_reasons": ["attempt-interrupted"]}
            attempts.append(attempt)
            progress.clear()
            report = await asyncio.wait_for(_validate_address(build, link, rounds, interface, address, progress), remaining)
            usable = has_https_response(report)
            attempt.update(https_response=usable, engine_errors=report.get("engine_errors", {}),
                           rejection_reasons=report.get("rejection_reasons", []))
            # An actual application response (including Cloudflare, geographic
            # denial or a rate limit) must never trigger endpoint rotation.
            if (usable or report.get("qualified")
                    or "invalid-or-unsafe-config" in report.get("rejection_reasons", [])
                    or report.get("engine_errors", {}).get("configuration-invalid")):
                break
    except asyncio.CancelledError:
        raise
    except (ValueError, KeyError, TypeError):
        report["qualified"] = False
        report["rejection_reasons"].append("invalid-or-unsafe-config")
    except asyncio.TimeoutError:
        report = progress.get("report", report)
        report["qualified"] = False
        browser_pending = report.get("browser_check", {}).get("reason") == "browser-queue-or-execution-pending"
        reason = "browser-queue-or-runtime-deadline-inconclusive" if browser_pending else "candidate-deadline-or-dns-timeout"
        report["rejection_reasons"].append(reason)
        if browser_pending:
            report["validation_outcome"] = "inconclusive"
            report["browser_check"]["reason"] = reason
        if attempts:
            attempts[-1].update(https_response=has_https_response(report), engine_errors=report.get("engine_errors", {}),
                                rejection_reasons=list(report["rejection_reasons"]))
    except OSError:
        report["qualified"] = False
        report["rejection_reasons"].append("server-dns-failed")
        report["engine_errors"]["dns-failed"] = 1
    report["attempted_address_count"] = len(attempts)
    report["endpoint_attempts"] = attempts
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
    if not isinstance(links, list) or len(links) > 150 or any(not isinstance(link, str) for link in links):
        raise ValueError("service validation accepts at most 150 candidate share URIs")
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
