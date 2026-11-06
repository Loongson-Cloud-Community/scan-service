"""Check the shared seam and the actual installed/filtering build artifacts."""

import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

from scan_agent_events.delivery import deliver_event


ROOT = Path(__file__).resolve().parents[2]


class SharedClientTests(unittest.TestCase):
    def test_both_adapters_call_the_same_delivery_function(self):
        for kind in ("rpm", "srpm"):
            with self.subTest(kind=kind):
                command = ROOT / f"{kind}-scan-agent/scripts/send-{kind}-event"
                adapter = runpy.run_path(str(command))
                self.assertIs(adapter["deliver_event"], deliver_event)
                self.assertNotIn("retry_delay", adapter)
                self.assertNotIn("send_event", adapter)
                self.assertFalse((command.parent.parent / f"libexec/{kind}-scan-agent/event_outbox.py").exists())

    def test_installed_commands_work_without_source_path_configuration(self):
        for kind in ("rpm", "srpm"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                env = {**os.environ, "JENKINS_AGENT_WORKDIR": directory,
                       "SCAN_RESULTS_PORTAL_URL": "http://portal:8080",
                       "SCAN_SERVICE_INGEST_TOKEN": "packaging-test-token"}
                for name in ("PYTHONPATH", "JOB_NAME", "BUILD_NUMBER"):
                    env.pop(name, None)
                result = subprocess.run([f"/usr/local/bin/send-{kind}-event", "replay"],
                                        env=env, cwd=directory, capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("0 pending", result.stdout)

    def test_filtered_build_context_excludes_secrets_and_unrelated_sources(self):
        context = Path("/filtered-context")
        if not context.is_dir():
            self.skipTest("requires the packaging test image")
        for name in (".env", ".git", "data", "scan-results-portal", "docs",
                     "rpm-scan-agent/.git", "rpm-scan-agent/tests",
                     "srpm-scan-agent/.git", "srpm-scan-agent/tests", "srpm-scan-agent/libexec"):
            with self.subTest(excluded=name):
                self.assertFalse((context / name).exists())
        # The classic builder can retain an empty parent for its Dockerfile,
        # even though the Dockerfile and every test source are excluded.
        self.assertFalse(any((context / "agent-common/tests").rglob("*")))
        for name in ("agent-common/install.py", "agent-common/scan_agent_events/delivery.py",
                     "rpm-scan-agent/scripts/send-rpm-event",
                     "rpm-scan-agent/libexec/rpm-scan-agent/scan",
                     "srpm-scan-agent/scripts/send-srpm-event"):
            with self.subTest(included=name):
                self.assertTrue((context / name).is_file())


if __name__ == "__main__":
    unittest.main()
