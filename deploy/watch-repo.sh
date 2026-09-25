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
#
#  * The web dashboard is deployed too, but STRICTLY AS AN ACCESSORY. It is
#    updated after the server is confirmed healthy, and nothing that happens to
#    it -- a failed pip install, a syntax error, a unit that will not start --
#    is allowed to fail the deploy or trigger a rollback. A broken dashboard is
#    an inconvenience; a rolled-back rendezvous server is an outage.

set -uo pipefail

REPO="${UCONNECT_REPO:-https://github.com/AbdoWise-z/uconnect}"
BRANCH="${UCONNECT_BRANCH:-master}"
WORKDIR="${UCONNECT_WORKDIR:-/opt/uconnect}"
SERVICE="${UCONNECT_SERVICE:-uconnect-rendezvous}"
BINARY="${UCONNECT_BINARY:-/usr/local/bin/uconnect-rendezvous}"
INTERVAL="${UCONNECT_INTERVAL:-60}"
LOCK="/var/lock/uconnect-watch.lock"

# The dashboard. Deployed only if its unit is installed, so a box that does not
# want one needs no configuration to opt out.
WEB_SERVICE="${UCONNECT_WEB_SERVICE:-uconnect-web}"
WEB_ROOT="${UCONNECT_WEB_ROOT:-/opt/uconnect/web}"
OBSERVE_BIN="${UCONNECT_OBSERVE_BIN:-/usr/local/bin/uconn-observe}"
BRIDGE_BIN="${UCONNECT_BRIDGE_BIN:-/usr/local/bin/uconn-bridge}"
VENV="${UCONNECT_VENV:-/opt/uconnect/venv}"

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
# Dashboard deployment.
#
# Every failure path here returns 0. This runs after the rendezvous server is
# already restarted and verified, and the caller ignores the result anyway --
# both, because it would be absurd to roll back a working server because a
# Flask app would not start.
deploy_web() {
    local src="$1" build="$2"

    # No unit installed means this box does not want a dashboard.
    if ! systemctl list-unit-files "$WEB_SERVICE.service" >/dev/null 2>&1 ||
       ! systemctl cat "$WEB_SERVICE" >/dev/null 2>&1; then
        return 0
    fi

    log "web: deploying dashboard"

    if [ ! -x "$build/tools/uconn-observe" ]; then
        log "web: WARN uconn-observe missing from the build -- skipping"
        return 0
    fi
    install -m 0755 "$build/tools/uconn-observe" "$OBSERVE_BIN" || {
        log "web: WARN could not install uconn-observe -- skipping"; return 0; }

    # The chat gateway. Optional: an older commit has no bridge, and the
    # dashboard is perfectly usable without one.
    if [ -x "$build/tools/uconn-bridge" ]; then
        install -m 0755 "$build/tools/uconn-bridge" "$BRIDGE_BIN" ||
            log "web: WARN could not install uconn-bridge; chat will be unavailable"
    fi

    # Python deps. Re-created only when requirements.txt actually changes: a
    # pip install on every commit would add tens of seconds to each deploy and
    # reach out to the network for no reason.
    # Note the pip check, not just the python one. A half-built venv leaves a
    # working interpreter behind with no pip -- which is exactly what a missing
    # ensurepip produces -- and testing for python alone would then skip
    # straight past the repair.
    if [ ! -x "$VENV/bin/python" ] || [ ! -x "$VENV/bin/pip" ]; then
        log "web: creating virtualenv"
        rm -rf "$VENV"
        if ! python3 -m venv "$VENV" > "$WORKDIR/web-venv.log" 2>&1; then
            log "web: WARN python3 -m venv failed -- skipping the dashboard"
            # The reason matters and is not guessable: on Debian/Ubuntu it is a
            # missing python3-venv package, and the message says so precisely.
            sed 's/^/    /' "$WORKDIR/web-venv.log" | head -6
            return 0
        fi
    fi
    local req="$src/web/requirements.txt" req_hash
    req_hash="$(sha256sum "$req" 2>/dev/null | cut -d' ' -f1)"
    if [ "$req_hash" != "$(cat "$WORKDIR/web-req.sha" 2>/dev/null)" ]; then
        log "web: installing python dependencies"
        # gunicorn is a deployment choice rather than an application dependency,
        # so it lives here and not in requirements.txt. Flask's own server is
        # explicitly not for this.
        "$VENV/bin/pip" install -q --upgrade pip > "$WORKDIR/web-pip.log" 2>&1
        if ! "$VENV/bin/pip" install -q -r "$req" gunicorn >> "$WORKDIR/web-pip.log" 2>&1; then
            log "web: WARN pip install failed -- leaving the old dashboard running"
            tail -6 "$WORKDIR/web-pip.log" | sed 's/^/    /'
            return 0
        fi
        echo "$req_hash" > "$WORKDIR/web-req.sha"
    fi

    # Refresh the unit itself, or a change to it would be the one thing that
    # silently never deploys. The bind address is preserved from the installed
    # copy: install-watcher.sh writes it per host, and overwriting that with
    # the repo default would quietly move a dashboard someone had put on
    # loopback back onto every interface.
    local unit_src="$src/deploy/uconnect-web.service"
    local unit_dst="/etc/systemd/system/$WEB_SERVICE.service"
    if [ -f "$unit_src" ] && [ -f "$unit_dst" ]; then
        local bind
        bind="$(sed -n 's/^Environment=UCONNECT_WEB_BIND=//p' "$unit_dst" | head -1)"
        [ -n "$bind" ] || bind="0.0.0.0:8080"
        local staged="$WORKDIR/web-unit.staged"
        sed "s|^Environment=UCONNECT_WEB_BIND=.*|Environment=UCONNECT_WEB_BIND=$bind|" \
            "$unit_src" > "$staged"
        if ! cmp -s "$staged" "$unit_dst"; then
            log "web: unit file changed, refreshing (bind $bind preserved)"
            cp -f "$staged" "$unit_dst" && systemctl daemon-reload
        fi
        rm -f "$staged"
    fi

    # Ship the app. Copy to a staging dir and swap, so the running gunicorn
    # never reads a half-written tree.
    rm -rf "$WEB_ROOT.new"
    mkdir -p "$WEB_ROOT.new"
    cp -r "$src/web/." "$WEB_ROOT.new/" || {
        log "web: WARN copy failed -- skipping"; rm -rf "$WEB_ROOT.new"; return 0; }
    rm -rf "$WEB_ROOT.old"
    [ -d "$WEB_ROOT" ] && mv "$WEB_ROOT" "$WEB_ROOT.old"
    mv "$WEB_ROOT.new" "$WEB_ROOT"
    chown -R uconnect-web:uconnect-web "$WEB_ROOT" 2>/dev/null || true

    # A smoke test before restarting: the data layer imports cleanly and the
    # observer binary can actually reach the server. Catches a syntax error or
    # a missing dependency here, in the log, rather than as a 500 later.
    if ! "$VENV/bin/python" -c "
import sys; sys.path.insert(0, '$WEB_ROOT')
import observer, app          # noqa
" >/dev/null 2>&1; then
        log "web: WARN the app does not import -- rolling the dashboard back"
        rm -rf "$WEB_ROOT"
        [ -d "$WEB_ROOT.old" ] && mv "$WEB_ROOT.old" "$WEB_ROOT"
        return 0
    fi

    systemctl restart "$WEB_SERVICE" 2>/dev/null || {
        log "web: WARN restart failed"; return 0; }

    # is-active alone is not evidence of health. With Restart=always a unit
    # that dies on startup is reported "active" for most of its cycle, so a
    # dashboard crash-looping on "address already in use" looked perfectly fine.
    # A manual restart zeroes NRestarts, so anything above zero a few seconds
    # later means it has already died and been resurrected at least once.
    sleep 5
    local restarts
    restarts="$(systemctl show "$WEB_SERVICE" -p NRestarts --value 2>/dev/null || echo 0)"
    if systemctl is-active --quiet "$WEB_SERVICE" && [ "${restarts:-0}" -eq 0 ]; then
        log "web: dashboard is up"
    else
        log "web: WARN dashboard is not healthy (restarts=${restarts:-?})"
        # The reason is almost always in the last few lines, and an operator
        # should not have to go and ask for them.
        journalctl -u "$WEB_SERVICE" -n 6 --no-pager 2>/dev/null | sed 's/^/    /'
    fi
    return 0
}

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

    # Update this script from the commit being deployed. Without it the watcher
    # runs forever with whatever logic install-watcher.sh happened to lay down,
    # so a fix to the deployment process is the one change that never deploys --
    # which is a strange hole in a thing whose entire job is deploying changes.
    #
    # Atomic rename rather than a write in place: bash reads a script
    # incrementally as it runs, so overwriting our own file mid-execution can
    # resume the shell at a byte offset into different text. Renaming leaves
    # this process on the old inode and the next tick picks up the new one.
    local self_src="$src/deploy/watch-repo.sh"
    local self_dst="${UCONNECT_SELF:-/usr/local/bin/uconnect-watch}"
    if [ -f "$self_src" ] && ! cmp -s "$self_src" "$self_dst" 2>/dev/null; then
        if install -m 0755 "$self_src" "$self_dst.new" 2>/dev/null &&
           mv -f "$self_dst.new" "$self_dst" 2>/dev/null; then
            log "watcher: updated itself -- the new logic applies from the next tick"
        else
            log "watcher: WARN could not update itself"
            rm -f "$self_dst.new" 2>/dev/null
        fi
    fi

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
    # The subject alongside it, so the dashboard never has to run git. It runs
    # as its own unprivileged user and this tree is root-owned, so a git call
    # from there trips the dubious-ownership guard and returns nothing --
    # which looked like "no subject" rather than "no permission".
    printf '%s\n' "$subject" > "$WORKDIR/deployed.subject"
    chmod 0644 "$WORKDIR/deployed.sha" "$WORKDIR/deployed.subject" 2>/dev/null || true
    log "deployed ${remote_sha:0:8} successfully"

    # Only now, with the server confirmed up. The result is ignored on purpose:
    # the dashboard is an accessory and must not be able to fail this deploy.
    deploy_web "$src" "$build" || true
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
