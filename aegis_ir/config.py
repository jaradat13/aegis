from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    audit_key_file: Path
    audit_log_file: Path
    baseline_dir: Path
    triage_dir: Path
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8765


def get_settings(state_dir: Path | None = None) -> Settings:
    root = state_dir or Path(os.environ.get("AEGIS_IR_STATE", "~/.local/state/aegis-ir")).expanduser()
    return Settings(
        state_dir=root,
        audit_key_file=root / "audit.key",
        audit_log_file=root / "audit.log.jsonl",
        baseline_dir=root / "baselines",
        triage_dir=root / "triage",
        dashboard_host=os.environ.get("AEGIS_IR_HOST", "127.0.0.1"),
        dashboard_port=int(os.environ.get("AEGIS_IR_PORT", "8765")),
    )


def ensure_state(settings: Settings) -> None:
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    settings.baseline_dir.mkdir(parents=True, exist_ok=True)
    settings.triage_dir.mkdir(parents=True, exist_ok=True)

