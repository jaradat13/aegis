from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .config import Settings, ensure_state


class AuditLog:
    def __init__(self, settings: Settings):
        self.settings = settings
        ensure_state(settings)
        self._key = self._load_or_create_key()

    def record(
        self,
        action: str,
        target: str,
        status: str,
        details: dict[str, Any] | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        previous_hash = self._last_entry_hash()
        entry = {
            "id": str(uuid4()),
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor or os.environ.get("USER", "unknown"),
            "action": action,
            "target": target,
            "status": status,
            "details": details or {},
            "previous_hash": previous_hash,
        }
        payload = self._canonical(entry)
        entry["signature"] = self._sign(payload)
        entry["entry_hash"] = hashlib.sha256(self._canonical(entry)).hexdigest()
        with self.settings.audit_log_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def entries(self, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.settings.audit_log_file.exists():
            return []
        lines = self.settings.audit_log_file.read_text(encoding="utf-8").splitlines()
        selected = lines[-limit:] if limit else lines
        return [json.loads(line) for line in selected if line.strip()]

    def verify(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        previous = ""
        for index, entry in enumerate(self.entries(), start=1):
            signature = entry.get("signature", "")
            entry_hash = entry.get("entry_hash", "")
            unsigned = {k: v for k, v in entry.items() if k not in {"signature", "entry_hash"}}
            if unsigned.get("previous_hash") != previous:
                errors.append(f"line {index}: previous_hash chain mismatch")
            expected_sig = self._sign(self._canonical(unsigned))
            if not hmac.compare_digest(signature, expected_sig):
                errors.append(f"line {index}: signature mismatch")
            expected_hash = hashlib.sha256(self._canonical({**unsigned, "signature": signature})).hexdigest()
            if not hmac.compare_digest(entry_hash, expected_hash):
                errors.append(f"line {index}: entry_hash mismatch")
            previous = entry_hash
        return not errors, errors

    def _load_or_create_key(self) -> bytes:
        key_file = self.settings.audit_key_file
        if key_file.exists():
            return base64.b64decode(key_file.read_text(encoding="utf-8"))
        key = os.urandom(32)
        key_file.write_text(base64.b64encode(key).decode("ascii"), encoding="utf-8")
        key_file.chmod(0o600)
        return key

    def _last_entry_hash(self) -> str:
        entries = self.entries(limit=1)
        return entries[0].get("entry_hash", "") if entries else ""

    def _sign(self, payload: bytes) -> str:
        digest = hmac.new(self._key, payload, hashlib.sha256).digest()
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def _canonical(entry: dict[str, Any]) -> bytes:
        return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")

