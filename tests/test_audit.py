from __future__ import annotations

import tempfile
import unittest

from aegis_ir.audit import AuditLog
from aegis_ir.config import get_settings


class AuditLogTest(unittest.TestCase):
    def test_audit_log_signs_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLog(get_settings(Path(tmp)))
            audit.record("test", "target", "completed", {"x": 1}, actor="tester")

            ok, errors = audit.verify()

            self.assertTrue(ok)
            self.assertEqual(errors, [])
            entry = audit.entries()[0]
            self.assertTrue(entry["signature"])
            self.assertTrue(entry["entry_hash"])

    def test_audit_log_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = get_settings(Path(tmp))
            audit = AuditLog(settings)
            audit.record("test", "target", "completed", {"x": 1}, actor="tester")
            text = settings.audit_log_file.read_text(encoding="utf-8").replace("completed", "failed")
            settings.audit_log_file.write_text(text, encoding="utf-8")

            ok, errors = AuditLog(settings).verify()

            self.assertFalse(ok)
            self.assertTrue(any("signature mismatch" in error for error in errors))


from pathlib import Path


if __name__ == "__main__":
    unittest.main()
