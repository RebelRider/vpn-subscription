#!/usr/bin/env python3
"""
Best50 builder.

Quality-first pipeline:
- fetch small, already-filtered upstream lists;
- keep VLESS only for the first release (the dominant/high-signal protocol);
- deduplicate;
- perform a REAL HTTP request through each candidate using sing-box;
- keep a rolling stability history;
- publish only the best N nodes.

The VLESS URI parser intentionally supports the common VLESS/Reality forms
found in public subscriptions. Unsupported transports are rejected rather
than guessed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import shutil
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


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Best50Builder/1.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read()
    text = raw.decode("utf-8", "ignore").strip()

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
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.search(r"vless://\S+", line, re.I)
        if m:
            found.append(m.group(0).rstrip("`),]"))
    return found


def fingerprint(link: str) -> str:
    return hashlib.sha256(link.encode()).hexdigest()


def q1(q: dict[str, list[str]], key: str, default: str = "") -> str:
    return q.get(key, [default])[0]


def vless_to_singbox(link: str, tag: str = "node") -> dict:
    """
    Convert the common VLESS URI variants to a sing-box outbound.

    Supported:
      - TCP
      - WebSocket
      - gRPC
      - HTTP
      - HTTPUpgrade
      - TLS / Reality
      - Vision flow

    Unsupported transports are rejected. This is deliberate: publishing a
    guessed conversion would create exactly the dead/broken nodes this
    project is designed to eliminate.
    """
    u = urlsplit(link)
    if u.scheme.lower() != "vless":
        raise ValueError("not VLESS")
    if not u.hostname or not u.port or not u.username:
        raise ValueError("missing host/port/uuid")

    q = parse_qs(u.query, keep_blank_values=True)
    network = q1(q, "type", "tcp").lower()
    security = q1(q, "security", "").lower()
    flow = q1(q, "flow", "")

    if network in ("xhttp", "splithttp", "quic", "kcp"):
        raise ValueError(f"unsupported transport: {network}")

    out = {
        "type": "vless",
        "tag": tag,
        "server": u.hostname,
        "server_port": u.port,
        "uuid": unquote(u.username),
    }

    if flow:
        out["flow"] = flow

    if security in ("tls", "reality"):
        tls = {
            "enabled": True,
            "server_name": q1(q, "sni") or q1(q, "host") or u.hostname,
        }

        fp = q1(q, "fp")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}

        alpn = q1(q, "alpn")
        if alpn:
            tls["alpn"] = [x for x in alpn.split(",") if x]

        if security == "reality":
            pbk = q1(q, "pbk") or q1(q, "publicKey")
            sid = q1(q, "sid") or q1(q, "shortId")
            if not pbk or not sid:
                raise ValueError("Reality without public key/short id")
            tls["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": sid,
            }

        out["tls"] = tls
    elif security in ("none", ""):
        pass
    else:
        raise ValueError(f"unsupported security: {security}")

    if network == "ws":
        path = unquote(q1(q, "path", "/"))
        headers = {}
        host = q1(q, "host")
        if host:
            headers["Host"] = host
        out["transport"] = {
            "type": "ws",
            "path": path,
            "headers": headers,
        }

    elif network == "grpc":
        service = unquote(q1(q, "serviceName", ""))
        if not service:
            raise ValueError("gRPC without serviceName")
        out["transport"] = {
            "type": "grpc",
            "service_name": service,
        }
        mode = q1(q, "mode")
        if mode:
            out["transport"]["idle_timeout"] = "15s"

    elif network == "http":
        path = unquote(q1(q, "path", "/"))
        host = q1(q, "host")
        out["transport"] = {
            "type": "http",
            "path": path,
            "host": [host] if host else [],
        }

    elif network == "httpupgrade":
        path = unquote(q1(q, "path", "/"))
        host = q1(q, "host")
        headers = {"Host": host} if host else {}
        out["transport"] = {
            "type": "httpupgrade",
            "path": path,
            "headers": headers,
        }

    # TCP needs no transport. If a V2Ray-style HTTP header is present,
    # map the common form instead of silently ignoring it.
    elif network == "tcp":
        header_type = q1(q, "headerType", "").lower()
        if header_type == "http":
            host = q1(q, "host")
            path = unquote(q1(q, "path", "/"))
            out["transport"] = {
                "type": "http",
                "host": [host] if host else [],
                "path": path,
            }
        elif header_type not in ("", "none"):
            raise ValueError(f"unsupported TCP headerType: {header_type}")

    return out


async def run_process(cmd: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    p = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return p.returncode, out, err
    except asyncio.TimeoutError:
        p.kill()
        await p.wait()
        return 124, b"", b"timeout"


async def probe_one(link: str, sem: asyncio.Semaphore, index: int) -> tuple[str, float | None]:
    async with sem:
        try:
            outbound = vless_to_singbox(link)
        except Exception as e:
            print(f"SKIP parse: {e}", file=sys.stderr)
            return link, None

        # Unique port per task avoids collisions between parallel probes.
        port = 22000 + index

        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / "config.json"
            cfg = {
                "log": {"level": "error"},
                "dns": {
                    "servers": [
                        {"type": "local", "tag": "local"}
                    ],
                    "final": "local"
                },
                "inbounds": [{
                    "type": "socks",
                    "tag": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": port
                }],
                "outbounds": [
                    outbound,
                    {"type": "direct", "tag": "direct"}
                ],
                "route": {"final": "node"}
            }
            # Ensure the outbound tag matches the route target.
            cfg["outbounds"][0]["tag"] = "node"
            cfg_path.write_text(json.dumps(cfg))

            check = await run_process(
                ["sing-box", "check", "-c", str(cfg_path)], 8
            )
            if check[0] != 0:
                return link, None

            proc = await asyncio.create_subprocess_exec(
                "sing-box", "run", "-c", str(cfg_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            try:
                await asyncio.sleep(0.25)
                start = time.perf_counter()
                code, out, _ = await run_process([
                    "curl",
                    "--socks5-hostname", f"127.0.0.1:{port}",
                    "--connect-timeout", str(CFG["connect_timeout"]),
                    "--max-time", str(CFG["request_timeout"]),
                    "-sS", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    CFG["test_url"],
                ], CFG["request_timeout"] + 2)

                elapsed = (time.perf_counter() - start) * 1000
                http_code = out.decode(errors="ignore").strip()

                if code == 0 and http_code.startswith(("2", "3")):
                    return link, elapsed
            finally:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()

        return link, None


def load_history() -> dict:
    p = ROOT / CFG["history_file"]
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def save_history(history: dict):
    (ROOT / CFG["history_file"]).write_text(
        json.dumps(history, ensure_ascii=False, indent=2, sort_keys=True)
    )


async def main_async():
    all_links = []

    for source in CFG["sources"]:
        try:
            text = await asyncio.to_thread(fetch, source["url"])
            links = extract_vless(text)
            print(f"{source['name']}: {len(links)} VLESS candidates")
            all_links.extend(links)
        except Exception as e:
            print(f"WARNING {source['name']}: {e}", file=sys.stderr)

    unique = {}
    for link in all_links:
        unique.setdefault(fingerprint(link), link)

    links = list(unique.values())[: CFG["candidate_limit"]]
    print(f"Unique VLESS candidates: {len(links)}")

    sem = asyncio.Semaphore(CFG["max_parallel"])
    results = await asyncio.gather(
        *(probe_one(link, sem, i) for i, link in enumerate(links))
    )

    history = load_history()
    now = int(time.time())
    good = []

    for link, latency in results:
        fp = fingerprint(link)
        item = history.get(fp, {
            "successes": 0,
            "failures": 0,
            "last_success": 0,
            "best_ms": None
        })

        if latency is not None:
            item["successes"] += 1
            item["last_success"] = now
            item["best_ms"] = (
                latency if item["best_ms"] is None
                else min(item["best_ms"], latency)
            )
            good.append((link, latency, item))
        else:
            item["failures"] += 1

        history[fp] = item

    save_history(history)

    scored = []
    for link, latency, item in good:
        # Strong preference for low latency, with modest stability bonuses.
        stability = min(item["successes"], 20) / 20
        age_h = max(0, (now - item["last_success"]) / 3600)
        recency = max(0.0, 1.0 - age_h / 24)
        score = latency - 120 * stability - 80 * recency
        scored.append((score, latency, link, item["successes"]))

    scored.sort(key=lambda x: (x[0], x[1]))
    chosen = scored[: CFG["max_output"]]

    lines = [
        "# Best50 — REAL-HTTP-TESTED public VLESS configurations",
        f"# generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(now))}",
        f"# candidates tested: {len(links)}",
        f"# working: {len(good)}",
        f"# published: {len(chosen)}",
        f"# test URL: {CFG['test_url']}",
        "# only VLESS is published in v1; unsupported configs are discarded",
    ]
    lines += [link for _, _, link, _ in chosen]
    (OUT / "best50.txt").write_text("\n".join(lines) + "\n")

    status = {
        "generated_at": now,
        "candidates": len(links),
        "working": len(good),
        "published": len(chosen),
        "test_url": CFG["test_url"],
        "top": [
            {
                "rank": i + 1,
                "latency_ms": round(lat, 1),
                "successes": successes,
                "fingerprint": fingerprint(link),
            }
            for i, (_, lat, link, successes) in enumerate(chosen)
        ],
    }
    (OUT / "status.json").write_text(json.dumps(status, indent=2))


if __name__ == "__main__":
    asyncio.run(main_async())
