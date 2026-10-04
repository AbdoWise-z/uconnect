"""Run the real deployment function against temporary paths and fake services."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DeployTests(unittest.TestCase):
    def test_issue67_recreated_environment_installs_unchanged_requirements(self):
        script = (ROOT / "deploy/watch-repo.sh").read_text()
        function = script[script.index("deploy_web() {"):]
        function = function[:function.index("\n}\n") + 3]
        with tempfile.TemporaryDirectory(prefix="uconnect-deploy-") as tmp:
            root = Path(tmp)
            (root / "src/web").mkdir(parents=True)
            (root / "build/tools").mkdir(parents=True)
            requirements = b"Flask\n"
            (root / "src/web/requirements.txt").write_bytes(requirements)
            (root / "web-req.sha").write_text(hashlib.sha256(requirements).hexdigest() + "\n")
            observe = root / "build/tools/uconn-observe"
            observe.write_text("#!/bin/sh\nexit 0\n")
            observe.chmod(0o755)
            harness = r'''
set -eu
WORKDIR="$1"
VENV="$WORKDIR/venv"
WEB_ROOT="$WORKDIR/web"
OBSERVE_BIN="$WORKDIR/observe"
WEB_SERVICE=uconnect-test-nonexistent
log() { :; }
systemctl() { if [ "$1" = show ]; then echo 0; fi; return 0; }
chown() { :; }
sleep() { :; }
python3() {
    mkdir -p "$VENV/bin"
    printf '#!/bin/sh\nexit 0\n' > "$VENV/bin/python"
    printf '#!/bin/sh\necho installed >> "%s/pip-ran"\n' "$WORKDIR" > "$VENV/bin/pip"
    chmod +x "$VENV/bin/python" "$VENV/bin/pip"
}
'''
            result = subprocess.run(["bash", "-c", harness + function +
                                     '\ndeploy_web "$WORKDIR/src" "$WORKDIR/build"\n',
                                     "test", tmp], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / "pip-ran").exists(), "new venv skipped dependency installation")


if __name__ == "__main__":
    unittest.main()
