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

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)     REPO="$2"; shift 2 ;;
        --branch)   BRANCH="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
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

systemctl daemon-reload
systemctl enable --now uconnect-watch.timer

echo
echo "watcher installed"
echo "  repo     : $REPO"
echo "  branch   : $BRANCH"
echo "  interval : ${INTERVAL}s"
echo
echo "  status : systemctl status uconnect-watch.timer"
echo "  logs   : journalctl -u uconnect-watch -f"
echo "  now    : sudo systemctl start uconnect-watch"
echo "  stop   : sudo systemctl disable --now uconnect-watch.timer"
echo
systemctl list-timers uconnect-watch.timer --no-pager 2>/dev/null | head -3 || true
