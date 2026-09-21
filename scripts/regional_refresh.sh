#!/bin/bash

set -uo pipefail

REPO="$HOME/best50-vpn-subscription"
PYTHON="/opt/homebrew/bin/python3"
SING_BOX="/opt/homebrew/bin/sing-box"

STATE_DIR="$HOME/Library/Application Support/best50-vpn"
STATE_FILE="$STATE_DIR/last-regional-pool-blob"
LOCK_DIR="$STATE_DIR/regional-refresh.lock"

LOG_PREFIX="[regional-refresh]"

log() {
    printf '%s %s %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S %z')" \
        "$LOG_PREFIX" \
        "$*"
}

cleanup() {
    rmdir "$LOCK_DIR" 2>/dev/null || true
}

fail() {
    log "ERROR: $*"
    exit 1
}

mkdir -p "$STATE_DIR" || exit 1

# Atomic PID-aware lock using mkdir.
#
# mkdir provides the atomic exclusion primitive. The PID file allows
# recovery after SIGKILL, process crash, or an interrupted machine
# session leaves the lock directory behind.
acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCK_DIR/pid" || {
            rmdir "$LOCK_DIR" 2>/dev/null || true
            fail "Unable to write lock PID."
        }
        return 0
    fi

    LOCK_PID=""

    if [ -f "$LOCK_DIR/pid" ]; then
        LOCK_PID="$(
            tr -dc '0-9' < "$LOCK_DIR/pid"
        )"
    fi

    if [ -n "$LOCK_PID" ] && kill -0 "$LOCK_PID" 2>/dev/null; then
        log "Another regional refresh is already running (PID $LOCK_PID); skipping."
        exit 0
    fi

    log "Recovering stale regional refresh lock${LOCK_PID:+ from PID $LOCK_PID}."

    rm -rf "$LOCK_DIR"         || fail "Unable to remove stale lock."

    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        fail "Unable to acquire lock after stale-lock recovery."
    fi

    printf '%s\n' "$$" > "$LOCK_DIR/pid" || {
        rm -rf "$LOCK_DIR" 2>/dev/null || true
        fail "Unable to write recovered lock PID."
    }
}

cleanup() {
    if [ -f "$LOCK_DIR/pid" ]; then
        OWNER_PID="$(
            tr -dc '0-9' < "$LOCK_DIR/pid"
        )"

        if [ "$OWNER_PID" != "$$" ]; then
            return
        fi
    fi

    rm -rf "$LOCK_DIR" 2>/dev/null || true
}

acquire_lock

trap cleanup EXIT INT TERM HUP

cd "$REPO" || fail "Repository not found: $REPO"

log "========================================"
log "REGIONAL REFRESH START"
log "========================================"

# Do not let an unattended automation mutate a dirty repository.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    fail "Tracked working tree is dirty; refusing unattended refresh."
fi

[ -x "$PYTHON" ] || fail "Python not executable: $PYTHON"
[ -x "$SING_BOX" ] || fail "sing-box not executable: $SING_BOX"
[ -f "scripts/local_probe.py" ] || fail "scripts/local_probe.py missing"

if ! ifconfig en0 >/dev/null 2>&1; then
    fail "Network interface en0 does not exist."
fi

EN0_IPV4="$(
    ipconfig getifaddr en0 2>/dev/null || true
)"

if [ -z "$EN0_IPV4" ]; then
    fail "en0 has no IPv4 address; skipping regional validation."
fi

log "en0 IPv4: $EN0_IPV4"

log "Fetching origin/main..."

if ! git fetch --quiet origin main; then
    fail "Unable to fetch origin/main."
fi

REMOTE_SHA="$(
    git rev-parse origin/main 2>/dev/null
)" || fail "Unable to resolve origin/main."

POOL_BLOB="$(
    git rev-parse \
        "origin/main:output/qualified-all.txt" \
        2>/dev/null
)" || fail "origin/main:output/qualified-all.txt does not exist."

log "origin/main SHA: $REMOTE_SHA"
log "qualified-all blob: $POOL_BLOB"

LAST_BLOB=""

if [ -f "$STATE_FILE" ]; then
    LAST_BLOB="$(
        tr -d '\r\n' < "$STATE_FILE"
    )"
fi

if [ "$POOL_BLOB" = "$LAST_BLOB" ]; then
    log "Candidate pool already processed; nothing to do."
    exit 0
fi

if [ -n "$LAST_BLOB" ]; then
    log "Candidate pool changed: $LAST_BLOB -> $POOL_BLOB"
else
    log "No previous automation state; current pool requires validation."
fi

log "Starting strict regional validation."

# local_probe.py itself:
# - fetches the current upstream pool,
# - forces VLESS probe outbounds through en0,
# - performs V5 functional gates,
# - requires 2/3 final rounds,
# - checks for stale upstream pool before publication,
# - publishes to the regional branch only after validation.
if ! "$PYTHON" scripts/local_probe.py \
    --interface en0 \
    --rounds 3 \
    --minimum-successes 2 \
    --publish
then
    fail "Regional validation/publication failed. Previous regional subscription remains unchanged."
fi

# Determine which pool was actually published.
# local_probe.py refuses stale publication, so origin/main should still
# contain the same candidate-pool blob after a successful publish.
if ! git fetch --quiet origin main; then
    fail "Publication succeeded, but post-publication origin/main verification fetch failed."
fi

LATEST_POOL_BLOB="$(
    git rev-parse \
        "origin/main:output/qualified-all.txt" \
        2>/dev/null
)" || fail "Unable to resolve post-publication candidate pool."

if [ "$LATEST_POOL_BLOB" != "$POOL_BLOB" ]; then
    fail "Candidate pool changed immediately after publication; leaving state unacknowledged so it will be tested again."
fi

TMP_STATE="${STATE_FILE}.tmp.$$"

printf '%s\n' "$POOL_BLOB" > "$TMP_STATE" \
    || fail "Unable to write temporary state."

mv "$TMP_STATE" "$STATE_FILE" \
    || fail "Unable to commit automation state."

log "Recorded processed pool blob: $POOL_BLOB"
log "REGIONAL REFRESH SUCCESS"
