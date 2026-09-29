#!/bin/bash

set -uo pipefail

REPO="${BEST50_REPO:-$HOME/best50-vpn-subscription}"
PYTHON="/opt/homebrew/bin/python3"
SING_BOX="/opt/homebrew/bin/sing-box"

STATE_DIR="$HOME/Library/Application Support/best50-vpn"

# Keep validation acknowledgement scoped to the checkout that actually
# performed the work. This prevents a manual development run from
# suppressing the dedicated production runtime, while manual bootstrap
# and launchd runs against the same runtime continue to share state.
CANONICAL_REPO="$(
    cd "$REPO" 2>/dev/null && pwd -P
)" || {
    printf '%s\n' "Unable to resolve repository path: $REPO" >&2
    exit 1
}

STATE_ID="$(
    printf '%s' "$CANONICAL_REPO" |
        /usr/bin/shasum -a 256 |
        /usr/bin/awk '{print substr($1,1,16)}'
)"

[ -n "$STATE_ID" ] || {
    printf '%s\n' "Unable to derive regional state identity." >&2
    exit 1
}

STATE_FILE="$STATE_DIR/regional-validation-state.$STATE_ID"
LEGACY_STATE_FILE="$STATE_DIR/last-regional-pool-blob"
LOCK_DIR="$STATE_DIR/regional-refresh.lock"

STATE_SCHEMA="regional-validation-v4-strict-local"

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

[ -f "scripts/update_exit_geoip.py" ] || fail "scripts/update_exit_geoip.py missing"

GEOIP_DIR="$STATE_DIR/geoip"
CITY_DB_IPV4="$GEOIP_DIR/dbip-city-ipv4.csv.gz"
CITY_DB_IPV6="$GEOIP_DIR/dbip-city-ipv6.csv.gz"

log "Refreshing actual-exit city GeoIP cache if stale."

if ! "$PYTHON" scripts/update_exit_geoip.py \
    --state-dir "$STATE_DIR" \
    --max-age-days 7
then
    log "WARNING: GeoIP updater failed unexpectedly; working VPN nodes will still be preserved."
fi

export BEST50_CITY_DB_IPV4="$CITY_DB_IPV4"
export BEST50_CITY_DB_IPV6="$CITY_DB_IPV6"

file_sha_or_missing() {
    if [ -f "$1" ]; then
        /usr/bin/shasum -a 256 "$1" |
            /usr/bin/awk '{print $1}'
    else
        printf '%s\n' "missing"
    fi
}

CITY_DB_IPV4_SHA="$(
    file_sha_or_missing "$CITY_DB_IPV4"
)"

CITY_DB_IPV6_SHA="$(
    file_sha_or_missing "$CITY_DB_IPV6"
)"


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

git_blob() {
    git rev-parse "origin/main:$1" 2>/dev/null
}

POOL_BLOB="$(
    git_blob "output/qualified-all.txt"
)" || fail "origin/main:output/qualified-all.txt does not exist."

LOCAL_PROBE_BLOB="$(
    git_blob "scripts/local_probe.py"
)" || fail "origin/main:scripts/local_probe.py does not exist."

BUILD_BLOB="$(
    git_blob "scripts/build.py"
)" || fail "origin/main:scripts/build.py does not exist."

CONFIG_BLOB="$(
    git_blob "config.json"
)" || fail "origin/main:config.json does not exist."

GEO_UPDATER_BLOB="$(
    git_blob "scripts/update_exit_geoip.py"
)" || fail "origin/main:scripts/update_exit_geoip.py does not exist."

CURRENT_STATE="$(
    printf '%s
' \
        "schema=$STATE_SCHEMA" \
        "pool=$POOL_BLOB" \
        "local_probe=$LOCAL_PROBE_BLOB" \
        "build=$BUILD_BLOB" \
        "config=$CONFIG_BLOB" \
        "geo_updater=$GEO_UPDATER_BLOB" \
        "city_ipv4=$CITY_DB_IPV4_SHA" \
        "city_ipv6=$CITY_DB_IPV6_SHA"
)"

log "origin/main SHA: $REMOTE_SHA"
log "qualified-all blob: $POOL_BLOB"
log "local_probe blob: $LOCAL_PROBE_BLOB"
log "build blob: $BUILD_BLOB"
log "config blob: $CONFIG_BLOB"
log "geo updater blob: $GEO_UPDATER_BLOB"
log "city IPv4 sha: $CITY_DB_IPV4_SHA"
log "city IPv6 sha: $CITY_DB_IPV6_SHA"

LAST_STATE=""

if [ -f "$STATE_FILE" ]; then
    LAST_STATE="$(
        tr -d '\r' < "$STATE_FILE"
    )"
fi

if [ -n "$LAST_STATE" ] && [ "$CURRENT_STATE" = "$LAST_STATE" ]; then
    log "Regional validation state already processed; nothing to do."
    exit 0
fi

if [ -n "$LAST_STATE" ]; then
    log "Regional validation state changed; revalidation required."
elif [ -f "$LEGACY_STATE_FILE" ]; then
    LEGACY_BLOB="$(
        tr -d '\r\n' < "$LEGACY_STATE_FILE"
    )"

    log "Legacy pool-only state detected: ${LEGACY_BLOB:-<empty>}"
    log "One-time migration to composite validation state required."
else
    log "No previous regional validation state; validation required."
fi

log "Starting strict regional validation."

# local_probe.py itself:
# - fetches the current upstream pool,
# - forces VLESS probe outbounds through en0,
# - performs V5 functional gates,
# - requires 5/5 complete final rounds,
# - checks for stale upstream pool before publication,
# - publishes to the regional branch only after validation.
if ! "$PYTHON" scripts/local_probe.py \
    --interface en0 \
    --rounds 5 \
    --minimum-successes 5 \
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
    git_blob "output/qualified-all.txt"
)" || fail "Unable to resolve post-publication candidate pool."

LATEST_LOCAL_PROBE_BLOB="$(
    git_blob "scripts/local_probe.py"
)" || fail "Unable to resolve post-publication local_probe.py."

LATEST_BUILD_BLOB="$(
    git_blob "scripts/build.py"
)" || fail "Unable to resolve post-publication build.py."

LATEST_CONFIG_BLOB="$(
    git_blob "config.json"
)" || fail "Unable to resolve post-publication config.json."

LATEST_GEO_UPDATER_BLOB="$(
    git_blob "scripts/update_exit_geoip.py"
)" || fail "Unable to resolve post-publication exit GeoIP updater."

LATEST_CITY_DB_IPV4_SHA="$(
    file_sha_or_missing "$CITY_DB_IPV4"
)"

LATEST_CITY_DB_IPV6_SHA="$(
    file_sha_or_missing "$CITY_DB_IPV6"
)"

LATEST_STATE="$(
    printf '%s
' \
        "schema=$STATE_SCHEMA" \
        "pool=$LATEST_POOL_BLOB" \
        "local_probe=$LATEST_LOCAL_PROBE_BLOB" \
        "build=$LATEST_BUILD_BLOB" \
        "config=$LATEST_CONFIG_BLOB" \
        "geo_updater=$LATEST_GEO_UPDATER_BLOB" \
        "city_ipv4=$LATEST_CITY_DB_IPV4_SHA" \
        "city_ipv6=$LATEST_CITY_DB_IPV6_SHA"
)"

if [ "$LATEST_STATE" != "$CURRENT_STATE" ]; then
    fail "Relevant origin/main validation inputs changed during the regional run; leaving state unacknowledged so the new state will be tested."
fi

TMP_STATE="${STATE_FILE}.tmp.$$"

printf '%s\n' "$CURRENT_STATE" > "$TMP_STATE" \
    || fail "Unable to write temporary composite state."

mv "$TMP_STATE" "$STATE_FILE" \
    || fail "Unable to commit composite automation state."

# The legacy file is no longer authoritative after a successful
# composite-state validation. Remove it only after the new state
# has been committed successfully.
rm -f "$LEGACY_STATE_FILE"

log "Recorded composite regional validation state."
log "REGIONAL REFRESH SUCCESS"
