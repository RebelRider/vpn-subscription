"""Stock, windowless macOS WebKit adapter for isolated ChatGPT proof.

The binary uses a fresh per-candidate data store and per-store proxy, never the
user's browser or system proxy. Candidate execution additionally uses Seatbelt.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import socket
import tempfile

from install_browser_runtime import RUNTIME
from owned_temporary import temporary_directory

MAX_SECONDS = 120
MAX_OUTPUT = 64 * 1024
SOURCE = Path(__file__).with_suffix(".swift")
_ISOLATION_VERIFIED = False


def native_sandbox_profile(port: int) -> str:
    from browser_probe import sandbox_profile
    # CFNetwork requires the resolver's local UNIX IPC even for a numeric proxy.
    # This does not permit any additional TCP/UDP socket or change macOS DNS.
    return sandbox_profile(port) + '(allow network-outbound (literal "/private/var/run/mDNSResponder"))'


def native_isolation_self_test() -> dict:
    from browser_probe import isolation_self_test
    proof = isolation_self_test(profile_factory=native_sandbox_profile)
    if proof.get("passed") is not True:
        return proof
    try:
        with tempfile.TemporaryDirectory(prefix="bestlocal-native-unix-") as directory, socket.socket(socket.AF_UNIX) as listener:
            path = str(Path(directory) / "denied.socket")
            listener.bind(path)
            listener.listen(1)
            result = subprocess.run(["/usr/bin/sandbox-exec", "-p", native_sandbox_profile(19123),
                                     sys.executable, "-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); print(s.connect_ex(sys.argv[1]))", path],
                                    capture_output=True, timeout=5, check=False)
            if result.returncode or result.stdout.strip() != b"1":
                return {"passed": False, "reason": "browser-isolation-test-failed"}
        return {"passed": True, "reason": "ok", "checks": {**proof.get("checks", {}), "unrelated_unix": 1}}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"passed": False, "reason": "browser-isolation-test-failed"}


def _failure(reason: str, *, available: bool = True) -> dict:
    return {"qualified": False, "rounds": [], "reason": reason,
            "method": "isolated-browser", "engine": "native-webkit", "available": available}


def _supported() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        return int(platform.mac_ver()[0].split(".")[0]) >= 14
    except (ValueError, IndexError):
        return False


def _owned_binary(path: Path) -> bool:
    try:
        info = path.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and info.st_mode & 0o077 == 0
                and info.st_mode & stat.S_IXUSR != 0 and 0 < info.st_size < 10 * 1024 * 1024)
    except OSError:
        return False


def ensure_binary() -> Path | None:
    """Compile trusted repository source atomically; call under the browser lease."""
    if not _supported() or not Path("/usr/bin/xcrun").is_file():
        return None
    try:
        content = SOURCE.read_bytes()
        if not 0 < len(content) < 128 * 1024:
            return None
        key = hashlib.sha256(content + platform.mac_ver()[0].encode()
                             + platform.machine().encode()).hexdigest()[:32]
        cache = RUNTIME / "native-webkit"
        cache.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = cache.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return None
        os.chmod(cache, 0o700)
        target = cache / ("probe-" + key)
        if _owned_binary(target):
            return target
        with temporary_directory(prefix="bestlocal-browser-", parent=RUNTIME.parent / "temporary") as directory:
            staging = Path(directory) / "probe"
            result = subprocess.run(["/usr/bin/xcrun", "swiftc", "-O", "-module-cache-path",
                                     str(Path(directory) / "modules"), str(SOURCE), "-o", str(staging)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=60, check=False)
            if result.returncode:
                return None
            os.chmod(staging, 0o700)
            if not _owned_binary(staging):
                return None
            os.replace(staging, target)
        return target
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def ensure() -> bool:
    """Probe compiler/cache availability without launching a browser process."""
    return ensure_binary() is not None


def validate_result(value: object, rounds: int, port: int | None, control: bool) -> dict:
    from browser_probe import validate_evidence
    if (not isinstance(value, dict) or value.get("engine") != "native-webkit"
            or type(value.get("available")) is not bool):
        return _failure("browser-invalid-evidence")
    if value["available"] is False:
        return _failure("browser-runtime-unavailable", available=False)
    result = validate_evidence(value, rounds)
    reason = value.get("reason")
    if not result["qualified"] and not value.get("rounds") and isinstance(reason, str) and re.fullmatch(r"[a-z-]{1,100}", reason):
        result["reason"] = reason
    result.update({"engine": "native-webkit", "available": True,
                   "proxy_port": None if control else port, "control": control})
    for key, low, high in (("network_error_code", -10000, 10000), ("proxy_challenges", 0, 20)):
        if type(value.get(key)) is int and low <= value[key] <= high:
            result[key] = value[key]
    if value.get("network_error_domain") in {"NSURLErrorDomain", "WKErrorDomain", "kCFErrorDomainCFNetwork", "other"}:
        result["network_error_domain"] = value["network_error_domain"]
    errors = value.get("underlying_errors")
    if isinstance(errors, list):
        result["underlying_errors"] = [{"domain": item["domain"], "code": item["code"]} for item in errors[:3]
                                       if isinstance(item, dict) and item.get("domain") in {"NSURLErrorDomain", "NSPOSIXErrorDomain", "kCFErrorDomainCFNetwork", "NWErrorDomain", "other"}
                                       and type(item.get("code")) is int and -100000 <= item["code"] <= 100000]
    return result


async def check_chatgpt(build, port: int | None, username: str | None, password: str | None,
                      rounds: int = 1, control: bool = False) -> dict:
    global _ISOLATION_VERIFIED
    from browser_probe import global_browser_slot, sandbox_profile
    if type(rounds) is not int or not 1 <= rounds <= 5:
        raise ValueError("browser rounds must be 1..5")
    if type(control) is not bool:
        raise ValueError("control must be boolean")
    if not control:
        sandbox_profile(port)
        if any(not isinstance(value, str) or not value or len(value.encode()) > 256
               or any(ord(char) < 32 for char in value) for value in (username, password)):
            return _failure("browser-proxy-authentication-missing")
    if not _supported():
        return _failure("browser-runtime-unavailable", available=False)
    loop = asyncio.get_running_loop()
    queued_at = loop.time()
    async with global_browser_slot() as acquired:
        if not acquired:
            return {**_failure("browser-queue-deferred-inconclusive"), "browser_started": False,
                    "queued_wait_ms": max(0, int((loop.time() - queued_at) * 1000))}
        if not control and not _ISOLATION_VERIFIED:
            proof = await asyncio.to_thread(native_isolation_self_test)
            if proof.get("passed") is not True:
                return _failure(proof.get("reason", "browser-isolation-test-failed"), available=False)
            _ISOLATION_VERIFIED = True
        binary = await asyncio.to_thread(ensure_binary)
        if binary is None:
            return _failure("browser-runtime-unavailable", available=False)
        environment = {key: value for key, value in os.environ.items()
                       if key in {"HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "LC_ALL", "__CF_USER_TEXT_ENCODING"}}
        process = None
        with temporary_directory(prefix="bestlocal-browser-", parent=RUNTIME.parent / "temporary") as directory:
            path = Path(directory) / "configuration.json"
            with path.open("x", encoding="utf-8") as stream:
                os.chmod(path, 0o600)
                json.dump({"control": control, "port": port, "username": username,
                           "password": password, "rounds": rounds}, stream)
            environment["BESTLOCAL_BROWSER_CONFIGURATION"] = str(path)
            command = [str(binary)]
            if not control:
                command = ["/usr/bin/sandbox-exec", "-p", native_sandbox_profile(port), *command]
            supervisor = Path(__file__).with_name("regional_scheduler.py")
            command = [sys.executable, str(supervisor), "--supervise", str(os.getpid()), str(MAX_SECONDS), "--", *command]
            try:
                process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=environment)
                build._register_owned_probe_process(process)
                async def read_bounded():
                    output = bytearray()
                    while True:
                        chunk = await process.stdout.read(8192)
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > MAX_OUTPUT:
                            raise ValueError("browser output limit")
                    await process.wait()
                    return output
                output = await asyncio.wait_for(read_bounded(), MAX_SECONDS + 8)
                if process.returncode:
                    return _failure("browser-deadline" if process.returncode == 124 else "browser-process-failed",
                                    available=process.returncode == 124)
                return validate_result(json.loads(output), rounds, port, control)
            except asyncio.TimeoutError:
                return _failure("browser-deadline")
            except (OSError, ValueError, UnicodeError, RecursionError):
                return _failure("browser-runtime-failed", available=False)
            finally:
                if process is not None:
                    await build._stop_owned_probe_process(process)
