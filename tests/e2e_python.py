#!/usr/bin/env python3
"""End-to-end test of the C API from Python: a real rendezvous server and two
processes of examples/python/demo.py, each a Node in the shared library, that
must punch, handshake, exchange greetings, and see each other leave.

The same checks as scripts/smoke.sh, made against the Python demo, so they
cover the whole path a C API caller takes: ctypes, the topic table, the event
queue, and the wire underneath.

CTest passes this tree's binaries in $UCONNECT_SERVER and $UCONNECT_C_LIB;
run by hand it defaults to ./build's.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
EXE = ".exe" if sys.platform == "win32" else ""
SERVER = os.environ.get("UCONNECT_SERVER") or os.path.join(
    ROOT, "build", "server", "uconnect-rendezvous" + EXE)
DEMO = os.path.join(ROOT, "examples", "python", "demo.py")


def wait_for(path: str, pattern: str, proc: subprocess.Popen, seconds: float):
    """The first match of `pattern` in the file at `path`, once it appears."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with open(path, encoding="utf-8", errors="replace") as f:
            m = re.search(pattern, f.read())
        if m:
            return m
        if proc.poll() is not None:
            return None
        time.sleep(0.1)
    return None


def demo(*args: str) -> list:
    return [sys.executable, DEMO, *args]


def main() -> int:
    logs = tempfile.mkdtemp(prefix="uc-py-e2e-")
    log = {who: os.path.join(logs, f"{who}.log") for who in ("server", "alice", "bob")}
    out = {}
    failures = []

    with open(log["server"], "w") as srv_log:
        # Port 0: the server says which it bound, so runs never collide.
        server = subprocess.Popen([SERVER, "--port", "0"], stdout=srv_log, stderr=subprocess.STDOUT)
    try:
        m = wait_for(log["server"], r"listening on TCP\+UDP (\d+)", server, 20)
        if not m:
            print("FAIL: server did not start")
            print(open(log["server"]).read())
            return 1
        addr = f"127.0.0.1:{m.group(1)}"
        print(f"server up on {addr}")

        created = subprocess.run(demo("--server", addr, "--create"),
                                 capture_output=True, text=True, timeout=30)
        uri = re.search(r"uconn://[0-9a-f]+#[0-9a-f]+", created.stdout)
        if not uri:
            print("FAIL: could not create a topic")
            print(created.stdout, created.stderr)
            return 1
        topic = uri.group(0)
        print(f"topic: {topic[:40]}...")

        # Bob leaves well before alice on purpose: his shutdown sends a
        # wire-level close, and alice must still be running to observe it.
        procs = {}
        with open(log["alice"], "w") as a_log:
            procs["alice"] = subprocess.Popen(
                demo("--server", addr, "--topic", topic, "--name", "alice", "--seconds", "18"),
                stdout=a_log, stderr=subprocess.STDOUT)
        time.sleep(2)
        with open(log["bob"], "w") as b_log:
            procs["bob"] = subprocess.Popen(
                demo("--server", addr, "--topic", topic, "--name", "bob", "--seconds", "8"),
                stdout=b_log, stderr=subprocess.STDOUT)

        codes = {who: p.wait(timeout=60) for who, p in procs.items()}
        for who in ("alice", "bob", "server"):
            with open(log[who], encoding="utf-8", errors="replace") as f:
                out[who] = f.read()

        for who in ("alice", "bob"):
            print(f"\n=== {who} ===\n{out[who]}", end="")

        def expect(who: str, pattern: str, why: str) -> None:
            if not re.search(pattern, out[who]):
                failures.append(why)

        expect("alice", r"-> connected", "alice never connected")
        expect("bob", r"-> connected", "bob never connected")
        expect("alice", r"<- \w+: hello from bob", "alice got no message from bob")
        expect("bob", r"<- \w+: hello from alice", "bob got no message from alice")
        # Bob's shutdown reaches alice on the wire, and the reason with it, all
        # the way out through the event queue. "timed-out" would mean the
        # notice was lost; the idle timeout is far longer than this test.
        expect("alice", r"gone: shutting-down", "alice did not learn that bob shut down")
        for who, code in codes.items():
            if code != 0:
                failures.append(f"{who} exited {code}")
    finally:
        server.kill()
        server.wait()

    if failures:
        print(f"\n=== server ===\n{out.get('server', '')}")
        for f in failures:
            print(f"FAIL: {f}")
        print("\nPYTHON E2E TEST FAILED")
        return 1
    print("\nPYTHON E2E TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
