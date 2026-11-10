"""Bounded LM Studio lease for BestLocal discovery, never a VPN validator.

Only exact worker-owned model identifiers may be unloaded. Existing loaded
instances cause safe deferral: the API cannot prove another client's idleness.
CLI cold start uses the installed application in supported --run-as-service
mode. An uncertain desktop backend is left idle after model/server cleanup.
"""
from __future__ import annotations

import base64
import fcntl
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

MODEL_KEY = "mlx-community/Qwen3.8-27B-4bit"
PREFIX = "bestlocal-qwen-"
MAX_BYTES = 512 * 1024
MAX_CLI_BYTES = 64 * 1024
JOURNAL = "lmstudio-lease.json"
QUARANTINE = "lmstudio-lease-quarantine.json"


class LMStudioError(RuntimeError):
    """A fixed, credential-free operational reason, never a raw API error."""


class LMStudioBusy(LMStudioError):
    """Resources are not provably available; retry unattended later."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _atomic(path: Path, value: dict):
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, allow_nan=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _default_command(argv, timeout):
    with tempfile.TemporaryFile() as output:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        try:
            while child.poll() is None:
                if time.monotonic() >= deadline or output.tell() > MAX_CLI_BYTES:
                    raise LMStudioError("cli-timeout-or-output-limit")
                time.sleep(.05)
            if output.tell() > MAX_CLI_BYTES:
                raise LMStudioError("cli-output-limit")
            output.seek(0)
            return child.returncode, output.read(MAX_CLI_BYTES + 1).decode("utf-8")
        finally:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                    child.wait(timeout=3)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    pass
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)


def _process_info(pid):
    if type(pid) is not int or pid <= 1:
        return None
    try:
        started = subprocess.check_output(["/bin/ps", "-p", str(pid), "-o", "lstart="], timeout=3).decode().strip()
        executable = subprocess.check_output(["/bin/ps", "-p", str(pid), "-o", "comm="], timeout=3).decode().strip()
        if started and executable:
            return {"pid": pid, "started": started, "executable": executable}
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
    return None


def _available_memory():
    """Read macOS's reclaimable-memory estimate; never generate pressure."""
    try:
        total = int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=3))
        text = subprocess.check_output(["/usr/bin/memory_pressure", "-Q"], timeout=3).decode()
        match = re.search(r"System-wide memory free percentage:\s*(\d+)%", text)
        if match and 0 <= int(match[1]) <= 100:
            return total * int(match[1]) // 100
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeError):
        pass
    return None


def _terminate_owned_backend(identity):
    if _process_info(identity.get("pid")) != identity:
        return False
    try:
        os.kill(identity["pid"], signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False


class LMStudioLease:
    """``with LMStudioLease(config, state_dir, deadline) as lm: lm.complete(...)``.

    Deadline uses monotonic time. Test adapters are command(argv,timeout)->
    (code,text), http(method,base_url,path,payload,timeout)->dict,
    process_info(pid)->stable identity dict and available_memory()->bytes|None.
    No BestLocal global locks are acquired here; the orchestrator schedules this
    resource lease around validation and other AI workloads.
    """
    def __init__(self, config, state_dir, deadline, *, command=None, http=None,
                 clock=None, wall_clock=None, process_info=None, available_memory=None, terminate_process=None):
        self.config = dict(config or {})
        self.state_dir, self.deadline = Path(state_dir), deadline
        self.clock, self.wall_clock = clock or time.monotonic, wall_clock or time.time
        self.command = command or _default_command
        self.http_adapter = http
        self.process_info = process_info or _process_info
        self.available_memory = available_memory or _available_memory
        self.terminate_process = terminate_process or _terminate_owned_backend
        self.lms = str(self.config.get("lms_path", Path.home() / ".lmstudio/bin/lms"))
        self.port = self.config.get("port", 12431)
        self.context_length = self.config.get("context_length", 8192)
        self.ttl = self.config.get("model_ttl", 300)
        self.minimum_memory = self.config.get("minimum_available_bytes", 18 * 1024**3)
        if (self.config.get("model_key", MODEL_KEY) != MODEL_KEY
                or type(self.port) is not int or not 1024 <= self.port <= 65535
                or type(self.context_length) is not int or not 2048 <= self.context_length <= 16384
                or type(self.ttl) is not int or not 60 <= self.ttl <= 1800
                or type(self.minimum_memory) is not int or self.minimum_memory < 0
                or type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise LMStudioError("invalid-lease-configuration")
        self.base_url, self.model_identifier = None, None
        self.runtime_model_key, self.model_aliases = None, None
        self.diagnostics, self.journal, self.lock = [], {}, None
        # Credentials never enter the journal, diagnostics, command argv or a URL.
        self.token = os.environ.get("BESTLOCAL_LMSTUDIO_TOKEN") or os.environ.get("LM_STUDIO_API_KEY")

    def _event(self, action, outcome):
        self.diagnostics = (self.diagnostics + [{"action": action, "outcome": outcome}])[-64:]

    def _timeout(self, maximum):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise LMStudioError("lease-deadline")
        return min(maximum, remaining)

    def _cli(self, arguments, maximum=20, *, json_output=True):
        label = "cli-" + arguments[0]
        if arguments[0] in {"server", "daemon"} and len(arguments) > 1:
            label += "-" + arguments[1]
        self._event(label, "started")
        try:
            code, text = self.command([self.lms, *arguments], self._timeout(maximum))
            if type(code) is not int or code or not isinstance(text, str) or len(text.encode()) > MAX_CLI_BYTES:
                raise LMStudioError("cli-request-failed")
            value = json.loads(text) if json_output else None
            self._event(label, "completed")
            return value
        except LMStudioError:
            self._event(label, "failed")
            raise
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, TypeError):
            self._event(label, "failed")
            raise LMStudioError("cli-request-failed") from None

    def _http(self, method, path, payload=None, maximum=20):
        if not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{4,5}", self.base_url or ""):
            raise LMStudioError("nonlocal-api-refused")
        try:
            timeout = self._timeout(maximum)
            if self.http_adapter:
                value = self.http_adapter(method, self.base_url, path, payload, timeout)
            else:
                headers = {"Content-Type": "application/json"}
                if self.token:
                    headers["Authorization"] = "Bearer " + self.token
                req = urllib.request.Request(self.base_url + path, data=None if payload is None else
                                             json.dumps(payload, allow_nan=False).encode(), headers=headers, method=method)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
                with opener.open(req, timeout=timeout) as response:
                    raw = response.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise LMStudioError("api-output-limit")
                value = json.loads(raw)
            if not isinstance(value, dict) or len(json.dumps(value).encode()) > MAX_BYTES:
                raise LMStudioError("invalid-api-response")
            return value
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise LMStudioError("api-authentication-required" if code in (401, 403) else
                                "api-rate-limited" if code == 429 else "api-request-failed") from None
        except LMStudioError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError, urllib.error.URLError):
            raise LMStudioError("api-request-failed") from None

    def _server(self):
        value = self._cli(["server", "status", "--json"])
        if not isinstance(value, dict) or type(value.get("running")) is not bool:
            raise LMStudioError("invalid-server-status")
        if value["running"] and (type(value.get("port")) is not int or not 1024 <= value["port"] <= 65535):
            raise LMStudioError("invalid-server-status")
        return value

    def _backend(self):
        value = self._cli(["daemon", "status", "--json"])
        if not isinstance(value, dict) or value.get("status") not in {"running", "not-running"}:
            raise LMStudioError("invalid-backend-status")
        if value["status"] == "running" and (type(value.get("pid")) is not int or value["pid"] <= 1):
            raise LMStudioError("invalid-backend-status")
        return value

    def _instances(self):
        aliases = self._model_aliases()
        models = self._http("GET", "/api/v1/models").get("models")
        if not isinstance(models, list) or len(models) > 256:
            raise LMStudioError("invalid-model-inventory")
        instances = {}
        for model in models:
            if not isinstance(model, dict) or not isinstance(model.get("loaded_instances"), list):
                raise LMStudioError("invalid-model-inventory")
            for item in model["loaded_instances"]:
                identifier = item.get("id") if isinstance(item, dict) else None
                if not isinstance(identifier, str) or not 0 < len(identifier) <= 256 or identifier in instances:
                    raise LMStudioError("invalid-model-inventory")
                key = model.get("key")
                instances[identifier] = aliases.get(key.casefold(), key) if isinstance(key, str) else key
        return instances

    def _model_aliases(self):
        if self.model_aliases is not None:
            return self.model_aliases
        # indexedModelIdentifier/path describe installed files; modelKey is the
        # actual CLI/API load handle and can differ (or be renamed by the user).
        # Resolve from the live local inventory, never guess/download a model.
        models = self._cli(["ls", "--json"])
        if not isinstance(models, list) or len(models) > 256:
            raise LMStudioError("invalid-model-inventory")
        matches = []
        aliases = {MODEL_KEY.casefold(): MODEL_KEY}
        for item in models:
            if not isinstance(item, dict) or item.get("deviceIdentifier") not in (None, ""):
                continue
            if item.get("path") != MODEL_KEY and item.get("indexedModelIdentifier") != MODEL_KEY:
                continue
            key = item.get("modelKey")
            if (item.get("format") != "safetensors" or not isinstance(key, str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", key)):
                continue
            matches.append(key)
            aliases[key.casefold()] = MODEL_KEY
        if len(matches) != 1:
            raise LMStudioError("existing-local-model-unconfirmed")
        self.runtime_model_key, self.model_aliases = matches[0], aliases
        return aliases

    def _save(self, **changes):
        self.journal.update(changes)
        _atomic(self.state_dir / JOURNAL, self.journal)

    def _same_backend(self, journal):
        backend = self._backend()
        identity = journal.get("backend_identity")
        return (backend["status"] == "running" and isinstance(identity, dict)
                and backend["pid"] == identity.get("pid") and self.process_info(backend["pid"]) == identity)

    def _read_journal(self):
        path = self.state_dir / JOURNAL
        info = None
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 16384:
                raise ValueError()
            value = json.loads(path.read_text())
            if (not isinstance(value, dict) or value.get("schema") != 1
                    or not isinstance(value.get("nonce"), str) or not re.fullmatch(r"[0-9a-f]{24}", value["nonce"])
                    or value.get("model_identifier") != PREFIX + value["nonce"]
                    or value.get("model_key") != MODEL_KEY):
                raise ValueError()
            return value
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError, RecursionError):
            if self._quarantine_invalid_journal(path, info):
                return None
            raise LMStudioBusy("untrusted-resource-journal") from None

    def _quarantine_invalid_journal(self, path, original):
        """Discard no ownership guesses: only quarantine our private state data.

        A corrupt journal cannot authorize unloading anything. The next lease
        treats every existing instance as foreign until it exits or its TTL
        elapses. One bounded, marked envelope retains diagnostic bytes without
        accumulating corrupt files or overwriting an unrelated destination.
        """
        try:
            directory = self.state_dir.lstat()
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
                    or stat.S_IMODE(directory.st_mode) != 0o700 or original is None
                    or not stat.S_ISREG(original.st_mode) or original.st_uid != os.getuid()
                    or stat.S_IMODE(original.st_mode) != 0o600):
                return False
            target = self.state_dir / QUARANTINE
            try:
                previous = target.lstat()
            except FileNotFoundError:
                previous = None
            if previous is not None:
                if (not stat.S_ISREG(previous.st_mode) or previous.st_uid != os.getuid()
                        or stat.S_IMODE(previous.st_mode) != 0o600 or previous.st_size > 32768):
                    return False
                value = json.loads(target.read_text())
                if (not isinstance(value, dict) or set(value) != {
                        "schema", "component", "quarantined_at", "original_size", "truncated", "journal_base64"}
                        or value.get("schema") != 1 or value.get("component") != "bestlocal-qwen-invalid-lease-journal"):
                    return False
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size, info.st_mtime_ns)
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as source:
                if identity(os.fstat(source.fileno())) != identity(original):
                    return False
                raw = source.read(16384)
            _atomic(target, {"schema": 1, "component": "bestlocal-qwen-invalid-lease-journal",
                "quarantined_at": self.wall_clock(), "original_size": original.st_size,
                "truncated": original.st_size > len(raw), "journal_base64": base64.b64encode(raw).decode("ascii")})
            if identity(path.lstat()) != identity(original):
                return False
            path.unlink()
            self._event("cleanup", "invalid-journal-quarantined")
            return True
        except (OSError, ValueError, TypeError, RecursionError):
            return False

    def _cleanup(self, journal):
        if not journal:
            return
        try:
            if not any(journal.get(key) for key in ("backend_started", "server_started", "model_load_intent")):
                (self.state_dir / JOURNAL).unlink(missing_ok=True)
                return
            if not self._same_backend(journal):
                self._event("cleanup", "original-backend-gone")
                (self.state_dir / JOURNAL).unlink(missing_ok=True)
                return
            server = self._server()
            expected_port = journal.get("port")
            if not server["running"] or server.get("port") != expected_port:
                self._event("cleanup", "endpoint-ownership-unconfirmed")
                # The user may have stopped/adopted the endpoint. Relinquish
                # ownership instead of latching future runs indefinitely; a
                # still-loaded unique model retains its explicit idle TTL.
                (self.state_dir / JOURNAL).unlink(missing_ok=True)
                return
            self.base_url = "http://127.0.0.1:" + str(expected_port)
            inventory = self._instances()
            own = journal["model_identifier"]
            if own in inventory:
                if inventory[own] != MODEL_KEY:
                    raise LMStudioBusy("owned-instance-identity-mismatch")
                # Exact verified nonce, never an implicit selection or --all.
                self._cli(["unload", own], maximum=30, json_output=False)
                self._event("model-unload", "owned-instance-unloaded")
            inventory = self._instances()
            if own in inventory:
                self._event("cleanup", "owned-model-still-loaded")
                return
            if inventory:
                self._event("cleanup", "foreign-workload-preserved")
                (self.state_dir / JOURNAL).unlink(missing_ok=True)
                return
            if journal.get("server_started") is True and self._same_backend(journal):
                current = self._server()
                if current["running"] and current.get("port") == expected_port:
                    self._cli(["server", "stop"], maximum=20, json_output=False)
                    self._event("server-stop", "owned-server-stopped")
            # Desktop service can be adopted by the user without changing its
            # PID. Do not quit that application based merely on an earlier PID.
            if journal.get("backend_started"):
                if journal.get("backend_is_daemon") is True and self._same_backend(journal):
                    if self.terminate_process(journal["backend_identity"]):
                        self._event("backend-cleanup", "owned-daemon-stopped")
                    else:
                        self._event("backend-cleanup", "ownership-unconfirmed-left-idle")
                else:
                    self._event("backend-cleanup", "desktop-adoption-unconfirmed-left-idle")
            (self.state_dir / JOURNAL).unlink(missing_ok=True)
        except (LMStudioError, OSError, ValueError, TypeError):
            self._event("cleanup", "deferred-with-ttl-failsafe")

    def __enter__(self):
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = (self.state_dir / "lmstudio-lease.lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close(); self.lock = None
            raise LMStudioBusy("another-lm-lease-active") from None
        try:
            old = self._read_journal()
            if old:
                self._cleanup(old)
                if (self.state_dir / JOURNAL).exists():
                    raise LMStudioBusy("previous-lease-cleanup-pending")
            nonce = secrets.token_hex(12)
            self.model_identifier = PREFIX + nonce
            self.journal = {"schema": 1, "nonce": nonce, "model_key": MODEL_KEY,
                            "model_identifier": self.model_identifier, "created_at": self.wall_clock(),
                            "backend_started": False, "server_started": False, "model_load_intent": False}
            backend, server = self._backend(), self._server()
            self._save(phase="starting", port=server.get("port") if server["running"] else self.port)
            if backend["status"] == "not-running":
                self._save(phase="starting-backend")
                result = self._cli(["daemon", "up", "--json"], maximum=60)
                if not isinstance(result, dict) or result.get("status") != "running" or type(result.get("pid")) is not int:
                    raise LMStudioError("backend-start-failed")
                backend = result
                self._save(backend_started=True)
            identity = self.process_info(backend["pid"])
            if not isinstance(identity, dict) or identity.get("pid") != backend["pid"]:
                raise LMStudioBusy("backend-identity-unconfirmed")
            self._save(backend_identity=identity, backend_is_daemon=backend.get("isDaemon") is True)
            # Startup may restore a previously configured server. Such a server
            # is not worker-owned and must never be reconfigured or stopped.
            server = self._server()
            if not server["running"]:
                if not self._same_backend(self.journal):
                    raise LMStudioBusy("backend-changed")
                loaded = self._cli(["ps", "--json"])
                if not isinstance(loaded, list):
                    raise LMStudioError("invalid-model-inventory")
                if loaded:
                    raise LMStudioBusy("foreign-loaded-model-preserved")
                self._save(phase="starting-server", port=self.port)
                self._cli(["server", "start", "--bind", "127.0.0.1", "--port", str(self.port)], maximum=60, json_output=False)
                server = self._server()
                if not server["running"] or server["port"] != self.port:
                    raise LMStudioError("server-start-failed")
                self._save(server_started=True)
            self._save(port=server["port"], phase="checking-resources")
            self.base_url = "http://127.0.0.1:" + str(server["port"])
            if self._instances():
                raise LMStudioBusy("foreign-loaded-model-preserved")
            memory = self.available_memory()
            if type(memory) is not int or memory < self.minimum_memory:
                raise LMStudioBusy("insufficient-or-unconfirmed-memory")
            model_dir = Path(self.config.get("model_dir", Path.home() / ".lmstudio/models")) / MODEL_KEY
            if not (model_dir / "config.json").is_file() or not (model_dir / "model.safetensors.index.json").is_file():
                raise LMStudioError("existing-model-files-missing")
            # Write the unique intended identifier before loading: a timeout or
            # process crash can be recovered without touching any user model.
            self._model_aliases()
            self._save(phase="loading-model", model_load_intent=True, runtime_model_key=self.runtime_model_key)
            self._cli(["load", self.runtime_model_key, "--identifier", self.model_identifier,
                       "--context-length", str(self.context_length), "--parallel", "1", "--ttl", str(self.ttl), "--yes"],
                      maximum=180, json_output=False)
            inventory = self._instances()
            if inventory.get(self.model_identifier) != MODEL_KEY:
                raise LMStudioError("model-load-unconfirmed")
            if set(inventory) != {self.model_identifier}:
                raise LMStudioBusy("foreign-workload-appeared")
            self._save(phase="ready", model_loaded=True)
            self._event("lease", "ready")
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def complete(self, messages, max_tokens=1536):
        if type(max_tokens) is not int or not 1 <= max_tokens <= min(4096, self.context_length - 512):
            raise LMStudioError("invalid-output-budget")
        if (not isinstance(messages, list) or not 1 <= len(messages) <= 40
                or any(not isinstance(m, dict) or set(m) != {"role", "content"}
                       or m["role"] not in {"system", "user", "assistant", "tool"}
                       or not isinstance(m["content"], str) for m in messages)):
            raise LMStudioError("invalid-prompt")
        # A byte can become its own token in arbitrary source material. Reserve
        # generation and chat-template overhead instead of assuming English's
        # average characters/token applies to credentials, URLs or other scripts.
        if len(json.dumps(messages, ensure_ascii=False).encode()) > min(65536, self.context_length - max_tokens - 512):
            raise LMStudioError("context-budget-exceeded")
        inventory = self._instances()
        if inventory.get(self.model_identifier) != MODEL_KEY:
            raise LMStudioError("model-instance-lost")
        if set(inventory) != {self.model_identifier}:
            raise LMStudioBusy("foreign-workload-appeared")
        value = self._http("POST", "/v1/chat/completions", {"model": self.model_identifier,
            "messages": messages, "stream": False, "max_tokens": max_tokens, "temperature": .2}, maximum=300)
        try:
            choice = value["choices"][0]
            content = choice["message"].get("content")
            if choice.get("finish_reason") == "length":
                raise LMStudioError("model-output-truncated")
            if choice.get("finish_reason") != "stop" or not isinstance(content, str) or not 0 < len(content.encode()) <= 65536:
                raise ValueError()
            # Reasoning-only/truncated answers are not executable decisions.
            content = re.sub(r"\A\s*<think>.*?</think>\s*", "", content, count=1, flags=re.S)
            if not content.strip():
                raise ValueError()
            return content.strip()
        except (KeyError, IndexError, TypeError, ValueError):
            raise LMStudioError("model-output-incomplete") from None

    def __exit__(self, *args):
        try:
            if self.journal:
                self._cleanup(self.journal)
        finally:
            if self.lock is not None:
                fcntl.flock(self.lock, fcntl.LOCK_UN)
                self.lock.close(); self.lock = None


def cleanup_owned_resources(config, state_dir, deadline, **injections):
    """Recover a crashed worker's exact nonce; never starts infrastructure."""
    lease = LMStudioLease(config, state_dir, deadline, **injections)
    lease.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (lease.state_dir / "lmstudio-lease.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return [{"action": "cleanup", "outcome": "active-worker-preserved"}]
        journal = lease._read_journal()
        lease._cleanup(journal)
        return lease.diagnostics
