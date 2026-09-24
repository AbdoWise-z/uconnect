#!/usr/bin/env bash
# Install the repo watcher as a systemd timer.
#
#   sudo bash deploy/install-watcher.sh [--branch master] [--interval 60]
#
# A timer rather than a `while true; do ... sleep; done` service: each run gets
# its own journal entry, a hung build cannot wedge the watcher forever
# (TimeoutStartSec kills it), and a crashed run does not need supervision to
# recover -- the next tick just happens.

set -euo pipefail

REPO="${UCONNECT_REPO:-https://github.com/AbdoWise-z/uconnect}"
BRANCH="master"
INTERVAL="60"
WITH_WEB=0
WEB_BIND="0.0.0.0:8080"

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)      REPO="$2"; shift 2 ;;
        --branch)    BRANCH="$2"; shift 2 ;;
        --interval)  INTERVAL="$2"; shift 2 ;;
        --with-web)  WITH_WEB=1; shift ;;
        --web-bind)  WEB_BIND="$2"; WITH_WEB=1; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install -m 0755 "$HERE/watch-repo.sh" /usr/local/bin/uconnect-watch
mkdir -p /opt/uconnect

cat > /etc/systemd/system/uconnect-watch.service <<EOF
[Unit]
Description=uConnect: redeploy the rendezvous server when $BRANCH moves
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=UCONNECT_REPO=$REPO
Environment=UCONNECT_BRANCH=$BRANCH
ExecStart=/usr/local/bin/uconnect-watch --once

# Needs root: it installs a binary into /usr/local/bin and restarts a unit.
# Deliberately NOT locked down the way the server itself is -- it compiles code
# and manages services, so the hardening that suits a network daemon would just
# break it.
User=root

# A wedged build must not block every later tick. (RuntimeMaxSec is ignored
# for Type=oneshot -- systemd warns about it and carries on unbounded.)
TimeoutStartSec=900
EOF

cat > /etc/systemd/system/uconnect-watch.timer <<EOF
[Unit]
Description=uConnect: poll $REPO#$BRANCH every ${INTERVAL}s

[Timer]
OnBootSec=30s
OnUnitActiveSec=${INTERVAL}s
AccuracySec=5s
Unit=uconnect-watch.service

[Install]
WantedBy=timers.target
EOF

# ---------------------------------------------------------------------------
# Optional read-only dashboard, redeployed by the same watcher.
if [ "$WITH_WEB" -eq 1 ]; then
    # A dedicated account rather than DynamicUser: the app tree has to be owned
    # by something stable across restarts, and DynamicUser's uid is not.
    if ! id uconnect-web >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin uconnect-web \
            2>/dev/null || useradd --system --no-create-home --shell /sbin/nologin uconnect-web
    fi
    mkdir -p /opt/uconnect/web
    chown -R uconnect-web:uconnect-web /opt/uconnect/web

    # Actually build one in a temp dir. `python3 -m venv --help` succeeds even
    # when creation cannot -- the ensurepip module that venv needs is a separate
    # package on Debian/Ubuntu, and the help text is served by venv itself. A
    # --help check would pass here and then fail on the first deploy.
    _vt="$(mktemp -d)"
    if ! python3 -m venv "$_vt/probe" >"$_vt/log" 2>&1; then
        echo
        echo "WARNING: python3 cannot create a virtualenv on this host, so the"
        echo "         dashboard will not start. The reason:"
        sed 's/^/           /' "$_vt/log" | head -5
        echo "         Debian/Ubuntu: sudo apt install -y python3-venv"
        echo "         RHEL/Oracle:   sudo dnf install -y python3 python3-pip"
        echo
    fi
    rm -rf "$_vt"

    sed "s|^Environment=UCONNECT_WEB_BIND=.*|Environment=UCONNECT_WEB_BIND=$WEB_BIND|" \
        "$HERE/uconnect-web.service" > /etc/systemd/system/uconnect-web.service
    systemctl enable uconnect-web.service >/dev/null 2>&1 || true
fi

systemctl daemon-reload
systemctl enable --now uconnect-watch.timer

echo
echo "watcher installed"
echo "  repo     : $REPO"
echo "  branch   : $BRANCH"
echo "  interval : ${INTERVAL}s"
if [ "$WITH_WEB" -eq 1 ]; then
    echo "  dashboard: $WEB_BIND  (installed; the next deploy builds and starts it)"
    echo
    echo "  The dashboard is UNAUTHENTICATED and read-only. Everything it shows"
    echo "  is already public to anyone who can reach the rendezvous server."
    echo "  Open the port on the host AND in the cloud firewall:"
    echo "    sudo firewall-cmd --add-port=${WEB_BIND##*:}/tcp --permanent && sudo firewall-cmd --reload"
    echo "  logs : journalctl -u uconnect-web -f"
fi
echo
echo "  status : systemctl status uconnect-watch.timer"
echo "  logs   : journalctl -u uconnect-watch -f"
echo "  now    : sudo systemctl start uconnect-watch"
echo "  stop   : sudo systemctl disable --now uconnect-watch.timer"
echo
systemctl list-timers uconnect-watch.timer --no-pager 2>/dev/null | head -3 || true
