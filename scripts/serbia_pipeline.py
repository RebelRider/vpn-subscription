#!/usr/bin/env python3
"""Independent RS policy using the production discovery, validator and Git writer.

No proxy/VPN/system setting is changed. An empty, completed selection is valid;
failed or interrupted validation never replaces a previously published snapshot.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import local_probe
import regional_pool
import service_probe
from owned_temporary import temporary_directory, cleanup_owned_temporary
from regional_scheduler import Runner, atomic_json, input_metadata, log, parse_timestamp, retry_delay
from subscription_presentation import title as subscription_title

SERVICES = ("chatgpt", "youtube", "instagram", "spotify")
COUNTRY = "RS"
PROFILE = "serbia-strict-services-v1"
SUBSCRIPTION = "output/best-local-Serbia.txt"
STATUS = "output/local-status-Serbia.json"
REVALIDATE_SECONDS = 230 * 60
MAX_INPUT_AGE = 18 * 3600
MAX_RESULT_AGE = 6 * 3600
MAX_NODES = 12
STATE_NAME = "serbia-scheduler-status.json"


class PriorValidationUnconfirmed(RuntimeError):
    """A completed empty attempt cannot revoke inconclusive previous RS nodes."""


def client_compatibility(entry_count: int) -> dict:
    """Describe content availability without claiming an actual Happ import."""
    if type(entry_count) is not int or not 0 <= entry_count <= MAX_NODES:
        raise ValueError("Invalid Serbia client entry count")
    return {"client": "Happ", "format": "proxy-share-uris", "entries": entry_count,
            "availability": "verified-rs" if entry_count else "awaiting-verified-rs",
            "empty_subscription_import_supported": False, "import_verified": False,
            "empty_import_evidence": "user-confirmed-empty-uri-parse-error"}


def _state(path: Path) -> dict:
    try:
        if path.stat().st_size > 1024 * 1024:
            return {}
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 10**12


def due(state: dict, signature: str, now: float) -> bool:
    retry = state.get("next_retry_at", 0)
    if _number(retry) and now < retry <= now + 3600 + 300:
        return False
    stamp = state.get("last_completed_at", 0)
    return (not _number(stamp) or stamp > now or now - stamp >= REVALIDATE_SECONDS
            or state.get("last_signature") != signature)


def confirmed_empty_diagnostics(diagnostics: list) -> bool:
    """Initial empty selection needs some definitive evidence, not only outages."""
    return (isinstance(diagnostics, list) and len(diagnostics) <= 150
            and any(_definitive_rejection(item) for item in diagnostics))


def _definitive_rejection(diagnostic: dict) -> bool:
    if not isinstance(diagnostic, dict) or diagnostic.get("qualified") is True:
        return False
    if any(reason in diagnostic.get("rejection_reasons", []) for reason in
           ("proxy-start-or-network-failure", "loopback-proxy-unavailable", "request-process-failed")):
        # These failures do not establish that the owned validator ever became
        # usable; absence of a working test engine must not clear the old pool.
        return False
    # Recompute FAIL from bounded evidence; a bare or contradictory outcome
    # label alone must never erase a previously verified connection.
    from local_feedback import classify_diagnostic
    geo = diagnostic.get("exit_country_evidence")
    mismatch = ("observed-exit-country-mismatch" in diagnostic.get("rejection_reasons", [])
                or isinstance(geo, dict) and geo.get("reason") == "observed-exit-country-mismatch")
    if not mismatch:
        return diagnostic.get("outcome") == "fail" and classify_diagnostic(diagnostic) == "fail"
    if not isinstance(geo, dict) or geo.get("reason") != "observed-exit-country-mismatch":
        return False
    try:
        stamp = parse_timestamp(geo.get("checked_at"), "Serbia exit observation")
        if not 0 <= time.time() - stamp <= MAX_RESULT_AGE:
            return False
        observations = geo.get("observations")
        if not isinstance(observations, list) or not 1 <= len(observations) <= 3:
            return False
        for item in observations:
            address = ipaddress.ip_address(item["ip"])
            country = item.get("country", "")
            if (address.is_global and not address.is_multicast and "%" not in item["ip"]
                    and item.get("source") in {"cloudflare-trace", "country-is"}
                    and isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country)
                    and country not in {COUNTRY, "XX", "ZZ"}):
                return True
    except (ValueError, TypeError, KeyError, RuntimeError):
        pass
    return False


def protect_previous_nonempty(build, previous: dict | None, status: dict) -> None:
    """An unrelated rejection is not evidence that the old RS pool failed."""
    if status.get("nodes") or not isinstance(previous, dict) or not previous.get("nodes"):
        return
    try:
        # Historical proof is checked at its original completed validation time;
        # its age never grants a new pass or prevents a definitive current FAIL.
        stamp = parse_timestamp(previous.get("generated_at"), "previous Serbia validation")
        if stamp > time.time():
            return
        _validate_result(build, previous, now=stamp)
    except (ValueError, TypeError, RuntimeError, KeyError):
        # Corrupt metadata must remain repairable by a complete current result.
        return
    diagnostics = status.get("diagnostics", [])
    diagnostics = diagnostics if isinstance(diagnostics, list) else []
    by_id = {}
    for diagnostic in diagnostics[:150]:
        if isinstance(diagnostic, dict) and isinstance(diagnostic.get("id"), str):
            by_id.setdefault(diagnostic["id"], []).append(diagnostic)
    for node in previous["nodes"]:
        rechecks = by_id.get(node["id"], [])
        if len(rechecks) != 1 or not _definitive_rejection(rechecks[0]):
            raise PriorValidationUnconfirmed("Previous RS candidate has no definitive current rejection")


def _validate_result(build, status: dict, *, now: float | None = None) -> None:
    """Recompute the complete admission contract immediately before each push."""
    now = time.time() if now is None else now
    if not isinstance(status, dict) or status.get("algorithm") != PROFILE or status.get("required_services") != list(SERVICES):
        raise ValueError("Invalid Serbia policy result")
    generated = parse_timestamp(status.get("generated_at"), "Serbia validation")
    if generated > now or now - generated > MAX_RESULT_AGE:
        raise ValueError("Stale Serbia result")
    nodes = status.get("nodes")
    rounds = status.get("stability", {}).get("rounds")
    if (not isinstance(nodes, list) or not 0 <= len(nodes) <= MAX_NODES
            or type(rounds) is not int or not 3 <= rounds <= 5
            or status.get("stability", {}).get("qualified") != len(nodes)
            or status.get("stability", {}).get("minimum_successes") != rounds
            or status.get("retained_nodes")):
        raise ValueError("Invalid Serbia result inventory")
    seen = set()
    for rank, node in enumerate(nodes, 1):
        if not isinstance(node, dict) or node.get("rank") != rank:
            raise ValueError("Invalid Serbia node rank")
        parsed = build.parse_vless(node.get("link", ""))
        ident = build.normalized_fingerprint(parsed)
        if not isinstance(node.get("tested_server_ip"), str):
            raise ValueError("Serbia node is missing its tested transport address")
        connection = local_probe.connection_identity(build, local_probe.tested_connection_link(build, node))
        if ident != node.get("id") or connection in seen:
            raise ValueError("Invalid or duplicate Serbia node")
        seen.add(connection)
        if (not local_probe.valid_node_evidence(node, rounds, require_round_evidence=True,
                                               require_current_browser=True, required_services=SERVICES,
                                               reference_time=datetime.fromtimestamp(now, timezone.utc))
                or not service_probe.valid_exit_country_evidence(node.get("exit_country_evidence"), COUNTRY,
                                                                reference_time=now)
                or node.get("exit_country") != COUNTRY):
            raise ValueError("Serbia requires current four-service and actual RS egress proof")
        stamp = parse_timestamp(node.get("validated_at"), "Serbia node")
        if not generated - MAX_RESULT_AGE <= stamp <= generated + 5:
            raise ValueError("Serbia node proof timestamp is inconsistent")
    if status.get("result") != ("qualified" if nodes else "empty"):
        raise ValueError("Invalid Serbia empty-result classification")
    compatibility = status.get("client_compatibility")
    expected_compatibility = client_compatibility(len(nodes))
    legacy_compatibility = {**expected_compatibility, "empty_subscription_import_supported": None,
                            "empty_import_evidence": "user-reported-parse-error"}
    if "client_compatibility" in status and (
            not isinstance(compatibility, dict) or type(compatibility.get("entries")) is not int
            or not (compatibility.get("empty_subscription_import_supported") is None
                    or compatibility.get("empty_subscription_import_supported") is False)
            or compatibility.get("import_verified") is not False
            or compatibility not in (expected_compatibility, legacy_compatibility)):
        raise ValueError("Inconsistent Serbia client availability metadata")


def render(build, status: dict) -> str:
    _validate_result(build, status)
    header = subscription_title(status).replace("BL VPN [", "BL RS [", 1)
    if len(header.removeprefix("#profile-title: ")) > 25:
        raise ValueError("Serbia profile title exceeds Happ's 25-character limit")
    lines = ["# BestLocal Serbia: independently validated actual RS egress", header,
             "#profile-update-interval: 1", "#subscription-ping-onopen-enabled: 1",
             "#ping-type: proxy", "#check-url-via-proxy: https://www.gstatic.com/generate_204",
             "#subscriptions-sort-type: ping", f"# generated: {status['generated_at']}",
             "# Required: ChatGPT AND YouTube AND Instagram AND Spotify; median proxy HTTPS <500 ms",
             f"# local_qualified: {len(status['nodes'])}", f"#bestlocal-result: {status['result']}"]
    compatibility = client_compatibility(len(status["nodes"]))
    lines.append(f"#bestlocal-availability: {compatibility['availability']}; entries={compatibility['entries']}")
    if not status["nodes"]:
        lines.append("# No currently verified servers with actual Serbia egress; no substitute countries or historical entries.")
        lines.append("#bestlocal-happ-import: unverified-empty; client reported a parse error on the previous empty response")
    lines.extend(local_probe.published_link(
                     local_probe.tested_connection_link(build, node), node["rank"], COUNTRY,
                                           node.get("exit_city"), node.get("exit_ip"))
                 for node in status["nodes"])
    return "\n".join(lines) + "\n"


def _validate_inputs(runner: Runner, build, status: dict, manifest_path: Path, *, refresh=False) -> None:
    manifest_digest = status.get("input", {}).get("regional_manifest", {}).get("digest")
    best50_digest = status.get("input", {}).get("best50_digest")
    sha = status.get("upstream_sha")
    if (not isinstance(manifest_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", manifest_digest)
            or not isinstance(best50_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", best50_digest)
            or not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", sha)):
        raise ValueError("Serbia result is missing its frozen input identity")
    if refresh:
        runner.git("fetch", "--quiet", "origin", "main")
    regional_pool.validate_manifest_membership(
        build, status["nodes"], manifest_path, expected_digest=manifest_digest,
        expected_best50_sha=sha, expected_best50_digest=best50_digest)
    current_best50 = runner.git("show", "origin/main:output/best50.txt")
    current_digest = hashlib.sha256("\n".join(local_probe.read_links_text(current_best50, "Best50")).encode()).hexdigest()
    if current_digest != best50_digest:
        raise ValueError("Best50 changed during Serbia validation")


def publish(repo: Path, state_dir: Path, build, status: dict, manifest_path: Path) -> str:
    """One immutable branch transaction; retry against a fresh base, no force push."""
    status.setdefault("client_compatibility", client_compatibility(len(status.get("nodes", []))))
    runner = Runner(repo, time.monotonic() + 300)
    serialized = (json.dumps(status, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    try:
        for attempt in range(3):
            try:
                text = render(build, status)
                runner.git("fetch", "--quiet", "origin", "regional", "main")
                _validate_inputs(runner, build, status, manifest_path)
                base = runner.git("rev-parse", "refs/remotes/origin/regional")
                code, previous_raw = runner.run(["git", "show", f"{base}:{STATUS}"], "Serbia previous result", check=False)
                if code == 0:
                    try:
                        previous = json.loads(previous_raw)
                        if (not isinstance(previous, dict) or previous.get("algorithm") != PROFILE
                                or previous.get("required_services") != list(SERVICES)):
                            raise ValueError("Invalid prior policy metadata")
                        previous_time = parse_timestamp(previous.get("generated_at"), "published Serbia validation")
                        if previous_time > time.time():
                            raise ValueError("Future prior metadata has no timestamp authority")
                    except (ValueError, TypeError, RuntimeError):
                        # Corrupt prior metadata has no timestamp authority. A
                        # new complete snapshot repairs both whitelisted files.
                        previous, previous_time = None, 0
                    current_time = parse_timestamp(status["generated_at"], "Serbia validation")
                    if previous_time > current_time:
                        return "superseded"
                    if previous_time == current_time and previous != status:
                        raise ValueError("Conflicting Serbia snapshots have equal validation times")
                    # This guard uses the same immutable base as the subsequent
                    # commit. A racing writer forces a fresh fetch and recheck.
                    protect_previous_nonempty(build, previous, status)
                with temporary_directory(prefix="best50-regional-publish-", parent=state_dir / "temporary", repo=repo) as directory:
                    worktree = Path(directory) / "checkout"
                    try:
                        runner.git("worktree", "add", "--detach", str(worktree), base)
                        for path, raw in ((SUBSCRIPTION, text.encode()), (STATUS, serialized)):
                            target = worktree / path
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_bytes(raw)
                        work = Runner(worktree, runner.deadline)
                        try:
                            work.git("add", "-f", SUBSCRIPTION, STATUS)
                            code, _ = work.run(["git", "diff", "--cached", "--quiet"], "Serbia transaction diff", check=False)
                            if code not in (0, 1):
                                raise RuntimeError("Unable to inspect Serbia transaction")
                            if code:
                                changed = work.git("diff", "--cached", "--name-only").splitlines()
                                if not set(changed) <= {SUBSCRIPTION, STATUS}:
                                    raise RuntimeError("Serbia transaction changes unrelated paths")
                                # Revalidate all proof, manifest and exact output
                                # immediately before publishing the branch.
                                if (worktree / SUBSCRIPTION).read_text() != render(build, status):
                                    raise ValueError("Serbia text changed before publication")
                                work.git("-c", "user.name=best50-bot", "-c",
                                         "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                                         "commit", "-m", "chore: update independently verified Serbia subscription")
                                _validate_inputs(runner, build, status, manifest_path, refresh=True)
                                work.git("push", "origin", "HEAD:refs/heads/regional")
                        finally:
                            work.stop()
                    finally:
                        subprocess.run(["git", "worktree", "remove", "--force", str(worktree)], cwd=repo,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
                runner.git("fetch", "--quiet", "origin", "regional")
                for path, expected in ((SUBSCRIPTION, text.encode()), (STATUS, serialized)):
                    actual = subprocess.run(["git", "show", f"origin/regional:{path}"], cwd=repo,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
                    if actual != expected:
                        raise RuntimeError("Serbia publication verification failed")
                return "published"
            except PriorValidationUnconfirmed:
                raise
            except (RuntimeError, OSError, subprocess.SubprocessError):
                if attempt == 2:
                    raise RuntimeError("Serbia publication failed after bounded retries") from None
                time.sleep(2 ** (attempt + 1))
    finally:
        runner.stop()
    raise RuntimeError("Unconfirmed Serbia publication")


def _previous(repo: Path, runner: Runner) -> tuple[list[str], list[str]]:
    code, raw = runner.run(["git", "show", f"origin/regional:{STATUS}"], "Serbia prior inventory", check=False)
    if code:
        return [], []
    try:
        status = json.loads(raw)
        nodes = status.get("nodes", [])
        if status.get("algorithm") != PROFILE or not isinstance(nodes, list) or len(nodes) > MAX_NODES:
            return [], []
        return [node["link"] for node in nodes], [node["id"] for node in nodes]
    except (ValueError, TypeError, KeyError):
        return [], []


async def _validate(repo: Path, state_dir: Path, runner: Runner, upstream_sha: str, best50: list[str]) -> tuple[dict, Path]:
    local_probe.ensure_probe_network("en0")
    build = local_probe.load_build_module()
    native_ready = False
    if sys.platform == "darwin":
        from native_webkit_probe import ensure
        native_ready = await asyncio.to_thread(ensure)
    if not native_ready:
        from install_browser_runtime import ensure
        if not await asyncio.to_thread(ensure):
            raise RuntimeError("No working windowless ChatGPT validation runtime")
    build.CFG["_probe_default_interface"] = "en0"
    _, order = _previous(repo, runner)
    links, manifest = await asyncio.to_thread(regional_pool.collect_regional, build, best50, state_dir,
                                              best50_sha=upstream_sha, preferred_country=COUNTRY, limit=90)
    _, status = await local_probe.run_local_probe(build, links, 5, 5, "origin/main Best50 + independent Serbia exploration",
                                                 required_services=SERVICES, required_exit_country=COUNTRY,
                                                 state_dir=state_dir, previous_order=order)
    diagnostics = status.get("diagnostics", [])
    if not isinstance(diagnostics, list) or len(diagnostics) != status.get("input", {}).get("nodes"):
        raise RuntimeError("Incomplete Serbia validation output")
    attempted_browsers = [item.get("browser_check", {}) for item in diagnostics
                          if isinstance(item, dict) and item.get("browser_check", {}).get("attempted")]
    infrastructure_browser_errors = {"browser-runtime-failed", "browser-runtime-unavailable", "browser-check-unavailable",
                                     "browser-network-isolation-unavailable", "browser-isolation-test-failed",
                                     "browser-process-failed", "browser-proxy-authentication-missing"}
    if (not status.get("nodes") and attempted_browsers
            and all(item.get("reason") in infrastructure_browser_errors for item in attempted_browsers)):
        raise RuntimeError("Serbia browser infrastructure failed; empty selection is unconfirmed")
    if not status.get("nodes") and not confirmed_empty_diagnostics(diagnostics):
        raise RuntimeError("Only inconclusive Serbia results; previous publication preserved")
    # A successful functional test is still private until the frozen input
    # manifest explicitly authorizes public export.
    public = {node["id"] for node in manifest["nodes"] if node["public_publish_allowed"]}
    selected, identities = [], set()
    for node in status["nodes"]:
        if node["id"] not in public:
            continue
        if not service_probe.valid_exit_country_evidence(node.get("exit_country_evidence"), COUNTRY):
            continue
        identity = local_probe.connection_identity(build, local_probe.tested_connection_link(build, node))
        if identity in identities:
            continue
        identities.add(identity)
        node["rank"] = len(selected) + 1
        observations = node["exit_country_evidence"]["observations"]
        node.update(exit_country=COUNTRY, exit_country_source="same-proxy-country-consensus",
                    exit_ip=observations[-1]["ip"], country=COUNTRY)
        selected.append(node)
        if len(selected) == MAX_NODES:
            break
    status.update(algorithm=PROFILE, required_services=list(SERVICES), nodes=selected,
                  result="qualified" if selected else "empty", retained_nodes=[],
                  upstream_sha=upstream_sha)
    status["input"].update(best50_digest=manifest["best50_digest"], regional_manifest={"digest": manifest["manifest_digest"]},
                           regional_summary=manifest["summary"])
    status["stability"]["qualified"] = len(selected)
    status["countries"] = {COUNTRY: len(selected)} if selected else {}
    status["regional_source_feedback"] = regional_pool.apply_local_feedback(state_dir, status["diagnostics"])
    status["publication"] = {"subscription_path": SUBSCRIPTION, "status_path": STATUS, "branch": "regional"}
    status["client_compatibility"] = client_compatibility(len(selected))
    _validate_result(build, status)
    return status, Path(manifest["manifest_path"])


def run_once(repo: Path, state_dir: Path) -> int:
    repo, state_dir = repo.resolve(), regional_pool._state_directory(state_dir)
    state_path = state_dir / STATE_NAME
    with (state_dir / "serbia-pipeline.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("Serbia overlap skipped")
            return 0
        try:
            cleanup_owned_temporary(state_dir / "temporary", repos=[repo])
        except (OSError, ValueError, RuntimeError):
            log("Serbia owned temporary recovery deferred")
        state = _state(state_path)
        runner = Runner(repo, time.monotonic() + 35 * 60)
        try:
            runner.fetch()
            signature, generated = input_metadata(runner)
            now = time.time()
            if not due(state, signature, now):
                return 0
            if not 0 <= now - generated <= MAX_INPUT_AGE:
                raise RuntimeError("Best50 is stale; Serbia previous publication retained")
            runner.git("fetch", "--quiet", "origin", "regional")
            best50 = local_probe.read_links_text(runner.git("show", "origin/main:output/best50.txt"), "Best50")
            upstream_sha = runner.git("rev-parse", "origin/main")
            state.update(running=True, last_attempt_at=now, health="validating", recovered_interrupted=state.get("running") is True)
            atomic_json(state_path, state)
            # Same physical isolation and global validation lock as BestLocal.
            # A parallel manual validator defers this policy instead of adding
            # another four candidates/browser queue to the machine.
            with (state_dir.parent / "local-probe.lock").open("a+") as probe_lock:
                try:
                    fcntl.flock(probe_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError("Main local validator owns the validation slot") from None
                status, manifest_path = asyncio.run(asyncio.wait_for(
                    _validate(repo, state_dir, runner, upstream_sha, best50), timeout=30 * 60))
            atomic_json(state_dir / "last-result.json", status)
            state.update(health="publishing", last_tested=len(status.get("diagnostics", [])), last_qualified=len(status["nodes"]))
            atomic_json(state_path, state)
            publication = publish(repo, state_dir, local_probe.load_build_module(), status, manifest_path)
            if publication not in {"published", "superseded"}:
                raise RuntimeError("Serbia publication is unconfirmed")
            state.update(health="superseded" if publication == "superseded" else "empty" if not status["nodes"] else "published", running=False,
                         last_completed_at=parse_timestamp(status["generated_at"], "Serbia result"), last_signature=signature,
                         last_publication_confirmed_at=time.time(), last_publication_status=publication,
                         consecutive_failures=0, next_retry_at=0,
                         last_outcomes=dict(Counter(item.get("outcome", "unknown") for item in status["diagnostics"])))
            if publication == "published":
                state["last_publication_at"] = time.time()
                state["last_published_validation_at"] = state["last_completed_at"]
            state.pop("last_error", None)
            log(f"Serbia complete: tested={state['last_tested']} qualified={state['last_qualified']} publication={publication}")
            return 0
        except PriorValidationUnconfirmed:
            failures = state.get("consecutive_failures", 0)
            failures = failures + 1 if type(failures) is int and 0 <= failures < 1000 else 1
            state.update(health="retained_inconclusive", running=False, consecutive_failures=failures,
                         next_retry_at=time.time() + retry_delay(failures), last_failure_at=time.time(),
                         last_publication_status="retained", last_error="prior-rs-recheck-inconclusive")
            status.setdefault("publication", {}).update(status="retained-inconclusive", last_known_good_preserved=True)
            atomic_json(state_dir / "last-result.json", status)
            log("Serbia empty result deferred: prior RS candidates remain unconfirmed; published snapshot preserved")
            return 1
        except (Exception, KeyboardInterrupt) as exc:
            failures = state.get("consecutive_failures", 0)
            failures = failures + 1 if type(failures) is int and 0 <= failures < 1000 else 1
            state.update(health="infrastructure_failed", running=False, consecutive_failures=failures,
                         next_retry_at=time.time() + retry_delay(failures), last_failure_at=time.time(),
                         last_error=type(exc).__name__ + ": previous Serbia publication preserved")
            log(f"Serbia deferred ({type(exc).__name__}); independent main subscription remains untouched")
            return 1
        finally:
            runner.stop()
            state.update(running=False, last_scheduler_finished_at=time.time())
            atomic_json(state_path, state)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--state-dir", type=Path, default=local_probe.STATE_DIR / "serbia")
    args = parser.parse_args()
    return run_once(args.repo, args.state_dir)


if __name__ == "__main__":
    raise SystemExit(main())
