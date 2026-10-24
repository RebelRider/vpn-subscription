#!/usr/bin/env python3
"""Isolated browser evidence for ambiguous ChatGPT HTTP responses.

The candidate browser can connect only to its authenticated loopback proxy.
Control mode deliberately uses the existing system connection without changing
any network settings. Neither mode reads existing browser state or signs in.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

from install_browser_runtime import CACHE, RUNTIME, VERSION, find_node, package_version
from owned_temporary import temporary_directory

MAX_SECONDS = 120
MAX_OUTPUT = 64 * 1024
_BROWSER_LOCK = asyncio.Lock()
_ISOLATION_VERIFIED = False


@asynccontextmanager
async def global_browser_slot(timeout: float = 45):
    """Serialize control, scheduled and manual browsers across processes."""
    RUNTIME.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(RUNTIME / "browser.lock", os.O_CREAT | os.O_WRONLY, 0o600)
    acquired = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                await asyncio.sleep(min(0.1, max(0.001, deadline - time.monotonic())))
        yield acquired
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
        # Never unlink a lock inode: another waiter may already have it open.


def sandbox_profile(port: int) -> str:
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("invalid candidate proxy port")
    # Seatbelt's host grammar accepts localhost, not literal 127.0.0.1.
    # The browser itself is explicitly pointed at 127.0.0.1 on this exact port.
    return ('(version 1)(allow default)(deny network-outbound)'
            '(allow network-outbound (remote tcp "localhost:' + str(port) + '"))')


def isolation_self_test() -> dict:
    """Real local-only allow/deny test. No public address is contacted."""
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        return {"passed": False, "reason": "browser-network-isolation-unavailable"}
    with socket.socket() as allowed, socket.socket() as denied, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        for listener in (allowed, denied):
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
        udp.bind(("127.0.0.1", 0))
        ports = [sock.getsockname()[1] for sock in (allowed, denied, udp)]
        code = """import json,socket,sys
a,b,c=map(int,sys.argv[1:]); out={}
for name,port in [('allowed',a),('denied',b)]:
 s=socket.socket(); s.settimeout(1); out[name]=s.connect_ex(('127.0.0.1',port)); s.close()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try: u.sendto(b'owned-isolation-test',('127.0.0.1',c)); out['udp']=0
except OSError as e: out['udp']=e.errno
print(json.dumps(out))
"""
        try:
            process = subprocess.run(["/usr/bin/sandbox-exec", "-p", sandbox_profile(ports[0]), sys.executable,
                                      "-c", code, *map(str, ports)], capture_output=True, timeout=6, check=True)
            result = json.loads(process.stdout)
            # EPERM is the sandbox's refusal, rather than a missing listener.
            ok = result == {"allowed": 0, "denied": 1, "udp": 1}
            return {"passed": ok, "reason": "ok" if ok else "browser-isolation-test-failed", "checks": result}
        except (OSError, ValueError, subprocess.SubprocessError):
            return {"passed": False, "reason": "browser-isolation-test-failed"}


def _failure(reason: str) -> dict:
    return {"qualified": False, "rounds": [], "method": "isolated-browser", "reason": reason}


def validate_evidence(value: object, rounds: int, now: datetime | None = None) -> dict:
    """Reject incomplete, stale or malformed success; retain only known metadata."""
    now = now or datetime.now(timezone.utc)
    if (not isinstance(value, dict) or not isinstance(value.get("rounds"), list)
            or len(value["rounds"]) > rounds or not isinstance(value.get("qualified"), bool)):
        return _failure("browser-invalid-evidence")
    clean = []
    for item in value["rounds"]:
        if not isinstance(item, dict) or not isinstance(item.get("passed"), bool):
            return _failure("browser-invalid-evidence")
        try:
            checked = datetime.fromisoformat(item["checked_at"].replace("Z", "+00:00"))
            if checked.tzinfo is None or not -5 <= (now - checked).total_seconds() <= MAX_SECONDS + 30:
                return _failure("browser-invalid-evidence")
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
            return _failure("browser-invalid-evidence")
        reason = item.get("reason")
        if not isinstance(reason, str) or not 0 < len(reason) <= 100 or not all(char.isalnum() or char == "-" for char in reason):
            return _failure("browser-invalid-evidence")
        clean_item = {"passed": item["passed"], "reason": reason, "checked_at": checked.isoformat()}
        code = item.get("http_status")
        if isinstance(code, int) and not isinstance(code, bool) and 0 <= code <= 599:
            clean_item["http_status"] = code
        for key in ("composer", "actionable", "restriction_free", "application_json"):
            if isinstance(item.get(key), bool):
                clean_item[key] = item[key]
        kind = item.get("api_kind")
        if kind is None or (isinstance(kind, str) and kind in {"openai-auth-providers", "chatgpt-model-catalog"}):
            clean_item["api_kind"] = kind
        clean.append(clean_item)
        diagnostics = item.get("diagnostics")
        if isinstance(diagnostics, dict):
            metadata = {}
            for key in ("body_sha256", "title_sha256"):
                if isinstance(diagnostics.get(key), str) and re.fullmatch(r"[a-f0-9]{64}", diagnostics[key]):
                    metadata[key] = diagnostics[key]
            for key in ("body_characters", "inputs", "textareas", "contenteditables", "plaintext_editors", "any_editors", "textbox_roles", "scripts", "page_errors", "failed_requests", "service_json_responses", "textarea_visible", "textarea_prompt_id", "textarea_prompt_name", "textarea_semantic_placeholder", "textarea_semantic_label", "textarea_placeholder_present", "textarea_hidden_semantics", "textarea_opacity_zero", "turnstile_fields", "logged_out_actions", "script_failures", "auth_providers_status", "anon_models_status", "api_models_status"):
                if isinstance(diagnostics.get(key), int) and not isinstance(diagnostics[key], bool) and 0 <= diagnostics[key] <= 10000000:
                    metadata[key] = diagnostics[key]
            for key in ("login_gate", "application_error", "loading", "guest_action", "rejected_optional_cookies"):
                if isinstance(diagnostics.get(key), bool):
                    metadata[key] = diagnostics[key]
            if isinstance(diagnostics.get("final_path"), str) and diagnostics["final_path"] in {"/", "other"}:
                metadata["final_path"] = diagnostics["final_path"]
            category = diagnostics.get("category")
            if isinstance(category, str) and re.fullmatch("[a-z-]{1,100}", category):
                metadata["category"] = category
            api_observations = diagnostics.get("api_observations")
            if isinstance(api_observations, list):
                observations = []
                for api in api_observations[:24]:
                    if not isinstance(api, dict):
                        continue
                    path, status, content_type, keys = (api.get(key) for key in ("path", "status", "content_type", "keys"))
                    if (not isinstance(path, str) or not re.fullmatch(r"/[A-Za-z0-9_/:.\-]{1,159}", path)
                            or not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599
                            or not isinstance(content_type, str) or not re.fullmatch(r"[A-Za-z0-9.+/\-]{0,80}", content_type)
                            or not isinstance(keys, list)):
                        continue
                    observations.append({"path": path, "status": status, "content_type": content_type,
                                         "keys": [key for key in keys[:24] if isinstance(key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,47}", key)]})
                metadata["api_observations"] = observations
            clean[-1]["diagnostics"] = metadata
    passed = (len(clean) == rounds and all(item["passed"] is True and item.get("reason") == "ok"
              and item.get("composer") is True and item.get("application_json") is True
              and item.get("actionable") is True and item.get("restriction_free") is True
              and item.get("api_kind") in {"openai-auth-providers", "chatgpt-model-catalog"}
              and item.get("http_status") == 200 for item in clean))
    if value["qualified"] and not passed:
        return _failure("browser-invalid-evidence")
    result = {"qualified": value["qualified"] and passed, "rounds": clean,
              "method": "isolated-browser-composer-and-application-json"}
    if not clean:
        result["reason"] = "browser-application-proof-missing"
    return result


async def check_chatgpt(build, port: int | None, username: str | None, password: str | None,
                      rounds: int = 1, control: bool = False, headless: bool = False) -> dict:
    """Return bounded evidence, never browser content, cookies or credentials."""
    global _ISOLATION_VERIFIED
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 5:
        raise ValueError("browser rounds must be 1..5")
    if not isinstance(headless, bool):
        raise ValueError("headless must be boolean")
    if not control and (not isinstance(username, str) or not isinstance(password, str)
                        or not username or not password or len(username) > 256 or len(password) > 256):
        return _failure("browser-proxy-authentication-missing")
    if not control:
        sandbox_profile(port)
    node = find_node()
    if not node or package_version(RUNTIME / "node_modules/playwright") != VERSION:
        return _failure("browser-runtime-unavailable")
    async with _BROWSER_LOCK, global_browser_slot() as acquired:
        if not acquired:
            return _failure("browser-busy-inconclusive")
        if not control and not _ISOLATION_VERIFIED:
            proof = await asyncio.to_thread(isolation_self_test)
            if not proof["passed"]:
                return _failure(proof["reason"])
            _ISOLATION_VERIFIED = True
        environment = {name: value for name, value in os.environ.items()
                       if name in {"HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "LC_ALL", "DISPLAY", "__CF_USER_TEXT_ENCODING"}}
        # Browser requests use either the explicit candidate proxy or unchanged
        # macOS system networking, never ambient shell proxy credentials.
        environment["PLAYWRIGHT_BROWSERS_PATH"] = str(CACHE)
        environment["BESTLOCAL_PLAYWRIGHT"] = str(RUNTIME / "node_modules/playwright")
        configuration = {"control": control, "port": port, "username": username, "password": password,
                         "rounds": rounds, "headless": headless}
        process = None
        with temporary_directory(prefix="bestlocal-browser-", parent=RUNTIME.parent / "temporary") as directory:
            configuration["profile"] = str(Path(directory) / "profile")
            configuration_path = Path(directory) / "configuration.json"
            with configuration_path.open("x", encoding="utf-8") as stream:
                os.chmod(configuration_path, 0o600)
                json.dump(configuration, stream)
            environment["BESTLOCAL_BROWSER_CONFIGURATION"] = str(configuration_path)
            command = [node, str(Path(__file__).with_suffix(".js"))]
            if not control:
                command = ["/usr/bin/sandbox-exec", "-p", sandbox_profile(port), *command]
            # The supervisor kills only its owned command group on deadline or
            # parent death. Node's signal handler closes its owned browser too.
            supervisor = Path(__file__).with_name("regional_scheduler.py")
            command = [sys.executable, str(supervisor), "--supervise", str(os.getpid()), str(MAX_SECONDS), "--", *command]
            try:
                process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=environment)
                build._register_owned_probe_process(process)
                async def read_bounded():
                    data = bytearray()
                    while True:
                        chunk = await process.stdout.read(8192)
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > MAX_OUTPUT:
                            raise ValueError("browser output limit")
                    await process.wait()
                    return data
                output = await asyncio.wait_for(read_bounded(), MAX_SECONDS + 8)
                if process.returncode:
                    return _failure("browser-deadline" if process.returncode == 124 else "browser-process-failed")
                result = validate_evidence(json.loads(output), rounds)
                result["proxy_port"] = None if control else port
                result["control"] = control
                return result
            except asyncio.TimeoutError:
                return _failure("browser-deadline")
            except (OSError, ValueError, UnicodeError, RecursionError):
                return _failure("browser-runtime-failed")
            finally:
                if process is not None:
                    await build._stop_owned_probe_process(process)
