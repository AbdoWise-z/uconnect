"""Exercise the real chat /peers output with unauthenticated directory metadata."""
import os
import socket
import struct
import subprocess
import sys
import tempfile
from e2e_python import wait_for


def main():
    server_binary, chat_binary = sys.argv[1:]
    with tempfile.TemporaryDirectory() as work:
        log = os.path.join(work, "server.log")
        with open(log, "w") as output:
            server = subprocess.Popen([server_binary, "--port", "0"], stdout=output,
                                      stderr=subprocess.STDOUT)
        try:
            port = int(wait_for(log, r"listening on TCP\+UDP (\d+)", server, 20).group(1))
            topic = bytes.fromhex("12" * 16)
            meta = b"DIRECTORY_MARKER_\x1b[2J_\xc2\x9b_END"
            with socket.create_connection(("127.0.0.1", port), timeout=5) as owner:
                body = struct.pack("!BBBBI", 1, 2, 0, 0, 1)
                body += topic + bytes([1, 0, 0]) + struct.pack("!H", len(meta)) + meta
                owner.sendall(struct.pack("!H", len(body)) + body)
                assert owner.recv(1024)[2] == 2, "registration failed"
                result = subprocess.run(
                    [chat_binary, "--server", f"127.0.0.1:{port}", "--topic",
                     "uconn://" + topic.hex() + "#" + "34" * 32, "--nick", "tester"],
                    input=b"/peers\n/quit\n", capture_output=True, timeout=20)
                assert result.returncode == 0, result.stderr
                assert b"DIRECTORY_MARKER_" in result.stdout, result.stdout
                assert b"\x1b" not in result.stdout, repr(result.stdout)
                assert b"\xc2\x9b" not in result.stdout, repr(result.stdout)
        finally:
            server.terminate()
            server.wait(timeout=10)
    print("chat directory metadata is safe terminal text")


if __name__ == "__main__":
    main()
