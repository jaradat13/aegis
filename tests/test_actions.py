from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aegis_ir.actions import ResponseOrchestrator
from aegis_ir.audit import AuditLog
from aegis_ir.config import get_settings


def make_orchestrator(tmp_path):
    settings = get_settings(tmp_path)
    return ResponseOrchestrator(settings, AuditLog(settings))


class ActionTest(unittest.TestCase):
    def test_collect_triage_creates_tarball(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence.log"
            evidence.write_text("login from suspicious host\n", encoding="utf-8")
            orch = make_orchestrator(root / "state")

            result = orch.collect_triage("INC 1", [evidence], dry_run=False)

            package = Path(str(result.details["package"]))
            self.assertEqual(result.status, "completed")
            self.assertTrue(package.exists())
            self.assertIn(str(evidence), result.details["included"])

    def test_cron_baseline_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "etc"
            cron_d = source / "cron.d"
            cron_d.mkdir(parents=True)
            (cron_d / "backup").write_text("* * * * * root /bin/true\n", encoding="utf-8")
            destination = root / "restore"
            orch = make_orchestrator(root / "state")

            orch.save_cron_baseline("known good", source)
            result = orch.rollback_cron("known good", destination, dry_run=False)

            self.assertEqual(result.status, "completed")
            restored = (destination / "cron.d" / "backup").read_text(encoding="utf-8")
            self.assertTrue(restored.startswith("* * *"))

    def test_dry_run_records_without_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            orch = make_orchestrator(Path(tmp))

            result = orch.isolate_interface("eth-test", "unit test", dry_run=True)

            self.assertEqual(result.status, "dry_run")
            self.assertEqual(orch.audit.entries(limit=1)[0]["action"], "isolate_interface")


if __name__ == "__main__":
    unittest.main()
