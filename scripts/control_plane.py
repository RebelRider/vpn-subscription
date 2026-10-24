#!/usr/bin/env python3
"""Run one control-plane command through an ephemeral, en0-bound SOCKS proxy."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from owned_temporary import temporary_directory


def configuration(port: int, username: str, password: str) -> dict:
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "control", "listen": "127.0.0.1", "listen_port": port,
                      "users": [{"username": username, "password": password}]}],
        "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "en0", "domain_resolver": "doh"}],
        "dns": {"servers": [{"type": "https", "tag": "doh", "server": "1.1.1.1", "server_port": 443,
                              "path": "/dns-query", "tls": {"enabled": True, "server_name": "cloudflare-dns.com"},
                              "detour": "direct"}], "final": "doh"},
        "route": {"default_interface": "en0", "default_domain_resolver": "doh", "final": "direct"},
    }


def proxy_environment(username: str, password: str, port: int) -> dict:
    environment = os.environ.copy()
    for key in list(environment):
        if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            environment.pop(key)
    proxy = f"socks5h://{username}:{password}@127.0.0.1:{port}"
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        environment[name] = environment[name.lower()] = proxy
    environment["NO_PROXY"] = environment["no_proxy"] = "localhost,127.0.0.1,::1"
    # Command-local Git configuration overrides a pre-existing http.proxy without
    # changing the user's Git configuration or authentication helper.
    count = int(environment.get("GIT_CONFIG_COUNT", "0"))
    if not 0 <= count <= 100:
        raise RuntimeError("invalid Git environment configuration")
    environment.update({"GIT_CONFIG_COUNT": str(count + 1), f"GIT_CONFIG_KEY_{count}": "http.proxy", f"GIT_CONFIG_VALUE_{count}": proxy})
    return environment


def receive(connection, length: int) -> bytes:
    result = b""
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise OSError("SOCKS handshake ended early")
        result += part
    return result


def wait_authenticated(process, port: int, username: str, password: str) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("control-plane proxy failed to start")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25) as connection:
                connection.sendall(b"\x05\x01\x02")
                if receive(connection, 2) != b"\x05\x02":
                    raise RuntimeError("control-plane SOCKS authentication is required")
                user, password_bytes = username.encode(), password.encode()
                connection.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password_bytes)]) + password_bytes)
                if receive(connection, 2) != b"\x01\x00":
                    raise RuntimeError("control-plane SOCKS authentication failed")
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("control-plane proxy startup timed out")


def stop_owned(process) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def validate_command(command: list[str]) -> None:
    if command and Path(command[0]).name in {"git", "gh"}:
        return
    if (len(command) >= 2 and Path(command[0]).resolve() == Path(sys.executable).resolve()
            and Path(command[1]).resolve() == Path("scripts/local_probe.py").resolve()):
        return
    raise RuntimeError("control-plane wrapper accepts only Git, gh, or the local validator")


def run(command: list[str], *, engine: str = "/opt/homebrew/bin/sing-box") -> int:
    validate_command(command)
    proxy = child = None
    def interrupted(signum, _frame):
        signal.signal(signum, signal.SIG_IGN)
        raise KeyboardInterrupt
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        with temporary_directory(prefix="bestlocal-control-") as temporary:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            username, password = secrets.token_hex(12), secrets.token_hex(24)
            path = Path(temporary) / "config.json"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                json.dump(configuration(port, username, password), handle)
            subprocess.run([engine, "check", "-c", str(path)], check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Inherit the scheduler-owned process group so its watchdog can reap
            # this wrapper, the proxy, and all validator children together.
            proxy = subprocess.Popen([engine, "run", "-c", str(path)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            wait_authenticated(proxy, port, username, password)
            child = subprocess.Popen(command, env=proxy_environment(username, password, port), stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + 90 * 60
            while child.poll() is None:
                if proxy.poll() is not None:
                    raise RuntimeError("control-plane proxy exited during the command")
                if time.monotonic() >= deadline:
                    raise RuntimeError("control-plane command deadline exceeded")
                time.sleep(0.1)
            return child.returncode
    finally:
        try:
            stop_owned(child)
        finally:
            try:
                stop_owned(proxy)
            finally:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)


def main() -> int:
    command = sys.argv[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    try:
        return run(command)
    except (RuntimeError, OSError, subprocess.SubprocessError, KeyboardInterrupt):
        # Never emit command arguments, proxy credentials, or engine diagnostics.
        print("Control-plane command failed; isolated proxy resources cleaned", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
