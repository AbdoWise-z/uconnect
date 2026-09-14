#!/usr/bin/env bash
# Build and install the uConnect rendezvous server on an Oracle Cloud instance.
#
#   git clone <your repo> uconnect && cd uconnect
#   sudo bash deploy/oracle-setup.sh [--port 4433]
#
# Works on both Always Free shapes:
#   VM.Standard.A1.Flex  (ARM Ampere, up to 4 OCPU / 24 GB)  -- preferred
#   VM.Standard.E2.1.Micro (AMD, 1 GB)                        -- also fine
#
# THE ORACLE GOTCHA
#
# Oracle Cloud puts TWO firewalls in front of your instance, and opening only
# one is the single most common reason a server here appears dead:
#
#   1. The VCN Security List / Network Security Group  (cloud side)
#   2. iptables or firewalld ON the instance           (OS side)
#
# Oracle's stock images ship with an iptables INPUT chain that REJECTs
# everything except SSH. Even with the security list wide open, your UDP
# datagrams die at step 2 with no log and no ICMP. This script handles step 2.
# Step 1 you must do in the console -- see the instructions it prints at the end.

set -euo pipefail

PORT=4433
while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

echo "==> repo:  $REPO_DIR"
echo "==> arch:  $(uname -m)"
echo "==> port:  $PORT/udp"
echo

# ---------------------------------------------------------------------------
# 1. Toolchain
# ---------------------------------------------------------------------------
if command -v dnf >/dev/null 2>&1; then
    DISTRO=rhel
    echo "==> installing build tools (dnf)"
    dnf install -y gcc-c++ cmake make >/dev/null
elif command -v apt-get >/dev/null 2>&1; then
    DISTRO=debian
    echo "==> installing build tools (apt)"
    apt-get update -qq
    apt-get install -y -qq build-essential cmake >/dev/null
else
    echo "unsupported distro: need apt or dnf" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Build
#
# No external dependencies, so this is just a compiler and cmake. On the
# 4-OCPU ARM shape it takes well under a minute.
# ---------------------------------------------------------------------------
echo "==> building"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DUCONNECT_BUILD_TESTS=ON >/dev/null
make -C build -j"$(nproc)" >/dev/null

echo "==> running the test suite (this validates the crypto on THIS cpu)"
# Worth doing on ARM specifically: the RFC vectors for BLAKE2s, ChaCha20,
# Poly1305 and X25519 are the only thing that distinguishes a correct build
# from one that merely compiles.
./build/tests/uconnect_tests | tail -2

install -m 0755 build/server/uconnect-rendezvous /usr/local/bin/uconnect-rendezvous

# ---------------------------------------------------------------------------
# 3. OS firewall -- the step everyone misses
# ---------------------------------------------------------------------------
echo
echo "==> opening $PORT/udp on the instance firewall"

if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PORT/udp" >/dev/null
    firewall-cmd --reload >/dev/null
    echo "    firewalld: added $PORT/udp"
else
    # Oracle's images have a REJECT rule at the end of INPUT. A rule appended
    # after it never matches, so insert BEFORE it rather than using -A.
    if iptables -C INPUT -p udp --dport "$PORT" -j ACCEPT 2>/dev/null; then
        echo "    iptables: rule already present"
    else
        reject_line="$(iptables -L INPUT --line-numbers -n \
                        | awk '/REJECT|DROP/ {print $1; exit}')"
        if [ -n "$reject_line" ]; then
            iptables -I INPUT "$reject_line" -p udp --dport "$PORT" -j ACCEPT
            echo "    iptables: inserted at position $reject_line (before the REJECT)"
        else
            iptables -A INPUT -p udp --dport "$PORT" -j ACCEPT
            echo "    iptables: appended (no REJECT rule found)"
        fi
    fi

    # Persist, or it vanishes on reboot.
    if [ "$DISTRO" = debian ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent >/dev/null 2>&1 || true
        netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4
    else
        service iptables save >/dev/null 2>&1 || iptables-save > /etc/sysconfig/iptables
    fi
    echo "    iptables: saved"
fi

# ---------------------------------------------------------------------------
# 4. systemd
# ---------------------------------------------------------------------------
echo "==> installing systemd unit"
sed "s|--port 4433|--port $PORT|" deploy/uconnect-rendezvous.service \
    > /etc/systemd/system/uconnect-rendezvous.service
systemctl daemon-reload
systemctl enable --now uconnect-rendezvous >/dev/null 2>&1
sleep 1
systemctl --no-pager --lines=6 status uconnect-rendezvous || true

# ---------------------------------------------------------------------------
# 5. Verify
# ---------------------------------------------------------------------------
echo
echo "==> checking what the outside world sees"
# On a proper cloud instance this should report the instance's public IP with
# the port PRESERVED and no NAT. If the port differs, the path is translated
# and clients will not be able to reach you.
/usr/local/bin/uconnect-rendezvous --nat-check --port 0 2>&1 | sed -n '3,10p' || true

PUBLIC_IP="$(curl -s --max-time 5 https://api.ipify.org || echo '<your-public-ip>')"

cat <<EOF

============================================================================
 Instance side is done. NOW OPEN THE CLOUD FIREWALL -- this is separate.

 Console:
   Networking -> Virtual Cloud Networks -> <your VCN> -> Security Lists
     -> Default Security List -> Add Ingress Rules

     Stateless:    No
     Source Type:  CIDR
     Source CIDR:  0.0.0.0/0
     IP Protocol:  UDP
     Destination Port Range: $PORT

 Or with the OCI CLI:
   oci network security-list update --security-list-id <ocid> \\
     --ingress-security-rules '[{"protocol":"17","source":"0.0.0.0/0",
       "udpOptions":{"destinationPortRange":{"min":$PORT,"max":$PORT}}}]'

 Then point a client at it:
   uconn-chat --server $PUBLIC_IP:$PORT --create --nick you

 Logs:     journalctl -u uconnect-rendezvous -f
 Restart:  systemctl restart uconnect-rendezvous
============================================================================
EOF
