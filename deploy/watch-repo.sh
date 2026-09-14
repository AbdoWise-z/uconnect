#!/usr/bin/env bash
# Watch a git remote and redeploy the rendezvous server when it moves.
#
#   sudo bash deploy/install-watcher.sh          # install as a systemd timer
#   sudo /usr/local/bin/uconnect-watch --once    # run one check by hand
#
# Design notes, because the naive version of this is dangerous:
#
#  * It polls rather than taking a webhook. A webhook would need an inbound HTTP
#    listener, a second open port and a public endpoint -- on a box whose whole
#    point is that only UDP 4433 is exposed. Polling costs one conditional GET a
#    minute and needs nothing open.
#
#  * It builds in a SEPARATE tree from the running binary. A broken commit must
#    not be able to take down a server that is currently working.
#
#  * It refuses to install a build whose TESTS FAIL. This process sits on the
#    public internet; "it compiled" is not the bar.
#
#  * It keeps the previous binary and ROLLS BACK if the new one will not stay
#    running. A rendezvous server that crashloops is worse than a stale one.
#
#  * Restarting is genuinely cheap here: records live in memory with a 90s
#    expiry and clients re-register within one 20s keepalive, so a restart costs
#    a few seconds of new registrations and nothing else. There is no state to
#    migrate and no database to worry about.

set -uo pipefail

REPO="${UCONNECT_REPO:-https://github.com/AbdoWise-z/uconnect}"
BRANCH="${UCONNECT_BRANCH:-master}"
WORKDIR="${UCONNECT_WORKDIR:-/opt/uconnect}"
SERVICE="${UCONNECT_SERVICE:-uconnect-rendezvous}"
BINARY="${UCONNECT_BINARY:-/usr/local/bin/uconnect-rendezvous}"
INTERVAL="${UCONNECT_INTERVAL:-60}"
LOCK="/var/lock/uconnect-watch.lock"

ONCE=0
LOOP=0
FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --once)  ONCE=1; shift ;;
        --loop)  LOOP=1; shift ;;
        --force) FORCE=1; shift ;;
        --repo)  REPO="$2"; shift 2 ;;
        --branch) BRANCH="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
[ "$ONCE" -eq 0 ] && [ "$LOOP" -eq 0 ] && ONCE=1

log() { printf '%s  %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# ---------------------------------------------------------------------------
check_once() {
    local src="$WORKDIR/src"

    if [ ! -d "$src/.git" ]; then
        log "cloning $REPO ($BRANCH) into $src"
        mkdir -p "$WORKDIR"
        git clone --branch "$BRANCH" --depth 50 "$REPO" "$src" >/dev/null 2>&1 || {
            log "ERROR: clone failed"; return 1; }
    fi

    # Git refuses to operate on a tree owned by another user. The watcher runs
    # as root and owns this one, but the guard still trips if anyone ever pokes
    # at it from a different account, and it fails in a way that looks like
    # "no new commits" rather than an error.
    git config --global --add safe.directory "$src" 2>/dev/null || true

    cd "$src" || return 1

    local local_sha remote_sha
    local_sha="$(git rev-parse HEAD 2>/dev/null)"

    # On a fresh clone local and remote already match, so a plain comparison
    # would never deploy anything. There is also no guarantee the binary
    # currently installed was built from this commit. Deploy once to establish
    # that it was.
    if [ ! -f "$WORKDIR/deployed.sha" ]; then
        log "no deployment on record -- building current HEAD to establish one"
        FORCE=1
    fi

    # Ask the remote directly. Cheaper than a fetch, and it means a network
    # blip costs nothing rather than leaving a half-updated tree.
    remote_sha="$(git ls-remote "$REPO" "refs/heads/$BRANCH" 2>/dev/null | cut -f1)"
    if [ -z "$remote_sha" ]; then
        log "WARN: cannot reach remote, skipping this round"
        return 0
    fi

    if [ "$local_sha" = "$remote_sha" ] && [ "$FORCE" -eq 0 ]; then
        return 0
    fi

    if [ "$local_sha" = "$remote_sha" ]; then
        log "redeploying ${remote_sha:0:8} (forced)"
    else
        log "new commit: ${local_sha:0:8} -> ${remote_sha:0:8}"
    fi

    git fetch --depth 50 origin "$BRANCH" >/dev/null 2>&1 || {
        log "ERROR: fetch failed"; return 1; }
    git reset --hard "origin/$BRANCH" >/dev/null 2>&1 || {
        log "ERROR: reset failed"; return 1; }
    git clean -fd >/dev/null 2>&1

    local subject
    subject="$(git log -1 --pretty=%s)"
    log "building ${remote_sha:0:8}: $subject"

    # Build in a tree separate from anything the running service touches.
    local build="$WORKDIR/build"
    if ! cmake -S "$src" -B "$build" -DCMAKE_BUILD_TYPE=Release \
               -DUCONNECT_BUILD_TESTS=ON > "$WORKDIR/last-build.log" 2>&1; then
        log "ERROR: cmake configure failed -- see $WORKDIR/last-build.log"
        return 1
    fi
    if ! make -C "$build" -j"$(nproc)" >> "$WORKDIR/last-build.log" 2>&1; then
        log "ERROR: build failed -- see $WORKDIR/last-build.log"
        return 1
    fi

    # Gate on the test suite. The RFC crypto vectors in particular are the only
    # thing distinguishing a correct build from one that merely compiles.
    log "running tests"
    if ! "$build/tests/uconnect_tests" > "$WORKDIR/last-test.log" 2>&1; then
        log "ERROR: TESTS FAILED -- refusing to deploy ${remote_sha:0:8}"
        tail -5 "$WORKDIR/last-test.log" | sed 's/^/    /'
        return 1
    fi
    log "tests passed: $(tail -1 "$WORKDIR/last-test.log")"

    # Keep the outgoing binary so a bad deploy can be undone.
    if [ -f "$BINARY" ]; then
        cp -f "$BINARY" "$BINARY.prev" 2>/dev/null || true
    fi

    install -m 0755 "$build/server/uconnect-rendezvous" "$BINARY" || {
        log "ERROR: install failed"; return 1; }

    log "restarting $SERVICE"
    systemctl restart "$SERVICE"

    # A service that starts and immediately dies still reports "activating" for
    # a moment, so give it a beat and then insist it is genuinely running.
    sleep 3
    if ! systemctl is-active --quiet "$SERVICE"; then
        log "ERROR: $SERVICE did not come up -- ROLLING BACK"
        if [ -f "$BINARY.prev" ]; then
            install -m 0755 "$BINARY.prev" "$BINARY"
            systemctl restart "$SERVICE"
            sleep 2
            if systemctl is-active --quiet "$SERVICE"; then
                log "rolled back to the previous binary; service is up"
            else
                log "CRITICAL: rollback did not restore the service"
            fi
        else
            log "CRITICAL: no previous binary to roll back to"
        fi
        return 1
    fi

    echo "$remote_sha" > "$WORKDIR/deployed.sha"
    log "deployed ${remote_sha:0:8} successfully"
    return 0
}

# ---------------------------------------------------------------------------
# One at a time. Overlapping runs would have two builds racing for the same
# tree and could install a half-written binary.
run_guarded() {
    flock -n 9 || { log "another check is already running, skipping"; return 0; }
    check_once
}

if [ "$LOOP" -eq 1 ]; then
    log "watching $REPO#$BRANCH every ${INTERVAL}s"
    while true; do
        ( run_guarded ) 9>"$LOCK"
        sleep "$INTERVAL"
    done
else
    ( run_guarded ) 9>"$LOCK"
    exit $?
fi
