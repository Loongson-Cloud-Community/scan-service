"""Process-lifecycle tests for an isolated agent container, using fake scanners."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCANNER = '''#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
from pathlib import Path
if sys.argv[1:] == ["--version"]:
    print("test-version")
    raise SystemExit(0)
mode = os.environ.get("TEST_MODE", "normal")
output = sys.argv[sys.argv.index("--output-file") + 1]
if mode in {"running", "ignore-term", "orphan"}:
    child = subprocess.Popen([sys.executable, "-c",
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(300)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=False)
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(os.environ["TEST_PIDS"]).write_text(json.dumps([os.getpid(), child.pid]))
    if mode != "orphan":
        while True:
            time.sleep(0.05)
for extension, content in (("json", "[]"), ("csv", "vendor,product"), ("html", "<html></html>")):
    Path(output + "." + extension).write_text(content)
print("scanner log", flush=True)
raise SystemExit(int(os.environ.get("TEST_EXIT", "0")))
'''

RPM_QUERY = '''#!/usr/bin/env python3
import os
from pathlib import Path
Path(os.environ["TEST_QUERIED"]).touch()
print("test\\n0\\n1\\n1\\nloongarch64\\ntest-1-1.src.rpm")
'''


def running(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


class ScanProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rpm-process-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        installed = self.bin / "run-rpm-scan"
        shutil.copyfile(ROOT / "scripts/run-rpm-scan", installed)
        installed.chmod(0o755)
        if (ROOT / "libexec").exists():
            shutil.copytree(ROOT / "libexec", self.root / "libexec")
        for name, content in (("cve-bin-tool", SCANNER), ("rpm", RPM_QUERY)):
            path = self.bin / name
            path.write_text(content)
            path.chmod(0o755)
        source = Path("/scan-input/test-1-1.loongarch64.rpm")
        source.write_bytes(b"test package")
        self.addCleanup(source.unlink, missing_ok=True)
        self.output = self.root / "output"
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.env = {
            **os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
            "XDG_CACHE_HOME": str(self.cache), "CVE_UPDATE_MODE": "never",
            "TEST_PIDS": str(self.root / "pids.json"),
            "TEST_QUERIED": str(self.root / "queried"),
        }
        self.processes = []
        self.addCleanup(self.stop_remaining)

    def start(self, **env):
        process = subprocess.Popen(
            [str(self.bin / "run-rpm-scan"), "test-1-1.loongarch64.rpm", str(self.output)],
            env={**self.env, **env}, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        self.processes.append(process)
        return process

    def wait_for(self, path):
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(path.exists(), "worker did not reach the expected phase")

    def stop_remaining(self):
        pids = [process.pid for process in self.processes]
        for record in self.root.glob("pids*.json"):
            pids.extend(json.loads(record.read_text()))
        for pid in pids:
            try:
                group = os.getpgid(pid)
                if group != os.getpgrp():
                    os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for process in self.processes:
            process.communicate(timeout=3)

    def assert_lock_released(self):
        with (self.cache / ".cve-db.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_normal_scan_keeps_reports_and_exit_code(self):
        proc = self.start()
        stdout, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 0, stderr)
        self.assertIn("scanner log", (self.output / "scan.log").read_text())
        manifest = json.loads((self.output / "scan-manifest.json").read_text())
        self.assertEqual(manifest["scanner"]["exit_code"], 0)
        self.assertIn("completed", stdout)
        self.assert_lock_released()

    def test_scan_needs_no_pipeline_context(self):
        for name in ("CURRENT_RPM_SHA256", "BUILD_NUMBER", "JOB_NAME", "WORKSPACE"):
            self.env.pop(name, None)
        proc = self.start()
        _, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 0, stderr)
        manifest = json.loads((self.output / "scan-manifest.json").read_text())
        self.assertEqual(manifest["rpm"]["sha256"], hashlib.sha256(b"test package").hexdigest())
        self.assertEqual(manifest["rpm"]["size_bytes"], len(b"test package"))

    def test_pipeline_private_hash_variable_is_ignored(self):
        proc = self.start(CURRENT_RPM_SHA256="not-a-digest")
        _, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 0, stderr)

    def test_findings_exit_one_remains_success(self):
        proc = self.start(TEST_EXIT="1")
        _, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 0, stderr)
        self.assertEqual(json.loads((self.output / "scan-manifest.json").read_text())["scanner"]["exit_code"], 1)

    def test_scanner_failure_is_preserved(self):
        proc = self.start(TEST_EXIT="2")
        _, stderr = proc.communicate(timeout=8)
        self.assertEqual(proc.returncode, 2, stderr)

    def test_term_stops_scanner_descendants_and_releases_lock(self):
        proc = self.start(TEST_MODE="running")
        self.wait_for(self.root / "pids.json")
        proc.send_signal(signal.SIGTERM)
        stdout, _ = proc.communicate(timeout=9)
        self.assertEqual(proc.returncode, 143)
        self.assertNotIn("completed", stdout)
        for pid in json.loads((self.root / "pids.json").read_text()):
            self.assertFalse(running(pid))
        self.assert_lock_released()

    def test_int_is_not_reported_as_success(self):
        proc = self.start(TEST_MODE="running")
        self.wait_for(self.root / "pids.json")
        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=9)
        self.assertEqual(proc.returncode, 130)
        self.assert_lock_released()

    def test_cancel_also_stops_a_term_ignoring_scanner(self):
        proc = self.start(TEST_MODE="ignore-term")
        self.wait_for(self.root / "pids.json")
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=9)
        self.assertEqual(proc.returncode, 143)
        self.assert_lock_released()

    def test_cancel_during_database_lock_wait(self):
        with (self.cache / ".cve-db.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            proc = self.start()
            self.wait_for(self.root / "queried")
            time.sleep(0.1)
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=9)
            self.assertEqual(proc.returncode, 143)
            self.assertFalse((self.root / "pids.json").exists())
        self.assert_lock_released()

    def test_normal_exit_does_not_leave_orphaned_lock_holders(self):
        proc = self.start(TEST_MODE="orphan")
        proc.communicate(timeout=9)
        self.assertEqual(proc.returncode, 0)
        self.assert_lock_released()

    def test_cancelling_one_scan_does_not_stop_another(self):
        first = self.start(TEST_MODE="running")
        self.wait_for(self.root / "pids.json")
        second = self.start(TEST_MODE="running", TEST_PIDS=str(self.root / "pids-other.json"))
        self.wait_for(self.root / "pids-other.json")
        first.send_signal(signal.SIGTERM)
        first.communicate(timeout=9)
        self.assertEqual(first.returncode, 143)
        self.assertIsNone(second.poll())
        for pid in json.loads((self.root / "pids-other.json").read_text()):
            self.assertTrue(running(pid))
        second.send_signal(signal.SIGTERM)
        second.communicate(timeout=9)
        self.assertEqual(second.returncode, 143)
        self.assert_lock_released()


if __name__ == "__main__":
    unittest.main()
