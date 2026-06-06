from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .audit import AuditLog
from .config import Settings, ensure_state


class CommandRunner(Protocol):
    def run(self, command: list[str]) -> subprocess.CompletedProcess[str]: ...


class SubprocessRunner:
    def run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, check=False, text=True)


@dataclass
class ActionResult:
    action: str
    target: str
    status: str
    dry_run: bool
    details: dict[str, object] = field(default_factory=dict)


class ResponseOrchestrator:
    def __init__(
        self,
        settings: Settings,
        audit: AuditLog | None = None,
        runner: CommandRunner | None = None,
    ):
        ensure_state(settings)
        self.settings = settings
        self.audit = audit or AuditLog(settings)
        self.runner = runner or SubprocessRunner()

    def kill_process(self, pid: int, reason: str, dry_run: bool = True) -> ActionResult:
        details: dict[str, object] = {"reason": reason, "signal": "SIGTERM"}
        status = "dry_run"
        if not dry_run:
            try:
                os.kill(pid, signal.SIGTERM)
                status = "completed"
            except ProcessLookupError:
                status = "failed"
                details["error"] = "process not found"
            except PermissionError:
                status = "failed"
                details["error"] = "permission denied"
        return self._finish("kill_process", str(pid), status, dry_run, details)

    def isolate_interface(self, interface: str, reason: str, dry_run: bool = True) -> ActionResult:
        command = ["ip", "link", "set", interface, "down"]
        details: dict[str, object] = {"reason": reason, "command": command}
        status = "dry_run"
        if not dry_run:
            completed = self.runner.run(command)
            status = "completed" if completed.returncode == 0 else "failed"
            details.update(
                {
                    "returncode": completed.returncode,
                    "stdout": completed.stdout[-2000:],
                    "stderr": completed.stderr[-2000:],
                }
            )
        return self._finish("isolate_interface", interface, status, dry_run, details)

    def collect_triage(
        self,
        incident_id: str,
        paths: list[Path] | None = None,
        dry_run: bool = True,
    ) -> ActionResult:
        incident = _safe_name(incident_id)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        package = self.settings.triage_dir / f"{incident}-{timestamp}.tar.gz"
        candidate_paths = paths or default_triage_paths()
        details: dict[str, object] = {
            "package": str(package),
            "requested_paths": [str(path) for path in candidate_paths],
            "included": [],
            "missing": [],
            "skipped": [],
        }
        if dry_run:
            return self._finish("collect_triage", incident_id, "dry_run", dry_run, details)

        with tarfile.open(package, "w:gz") as tar:
            for path in candidate_paths:
                expanded = path.expanduser()
                if not expanded.exists():
                    details["missing"].append(str(expanded))  # type: ignore[index]
                    continue
                self._add_triage_path(tar, expanded, package, details)
        return self._finish("collect_triage", incident_id, "completed", dry_run, details)

    def save_cron_baseline(self, name: str, source: Path | None = None) -> Path:
        source_path = source or Path("/etc")
        target = self.settings.baseline_dir / f"cron-{_safe_name(name)}"
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)

        copied = 0
        for cron_path in cron_paths(source_path):
            if cron_path.exists():
                destination = target / cron_path.relative_to(source_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if cron_path.is_dir():
                    shutil.copytree(cron_path, destination, dirs_exist_ok=True)
                else:
                    shutil.copy2(cron_path, destination)
                copied += 1
        self.audit.record("save_cron_baseline", name, "completed", {"files_or_dirs": copied})
        return target

    def rollback_cron(
        self,
        baseline: str,
        destination_root: Path | None = None,
        dry_run: bool = True,
    ) -> ActionResult:
        baseline_dir = self.settings.baseline_dir / f"cron-{_safe_name(baseline)}"
        destination = destination_root or Path("/etc")
        details: dict[str, object] = {
            "baseline": str(baseline_dir),
            "destination": str(destination),
            "restored": [],
        }
        if not baseline_dir.exists():
            return self._finish("rollback_cron", baseline, "failed", dry_run, {**details, "error": "baseline not found"})
        if dry_run:
            details["restored"] = [str(path.relative_to(baseline_dir)) for path in baseline_dir.rglob("*") if path.is_file()]
            return self._finish("rollback_cron", baseline, "dry_run", dry_run, details)

        for src in baseline_dir.rglob("*"):
            if src.is_dir():
                continue
            dest = destination / src.relative_to(baseline_dir)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)
            details["restored"].append(str(dest))  # type: ignore[index]
        return self._finish("rollback_cron", baseline, "completed", dry_run, details)

    def _finish(
        self,
        action: str,
        target: str,
        status: str,
        dry_run: bool,
        details: dict[str, object],
    ) -> ActionResult:
        details = {**details, "dry_run": dry_run}
        self.audit.record(action, target, status, details)
        return ActionResult(action=action, target=target, status=status, dry_run=dry_run, details=details)

    def _add_triage_path(
        self,
        tar: tarfile.TarFile,
        path: Path,
        package: Path,
        details: dict[str, object],
    ) -> None:
        excluded_roots = {package.resolve(), self.settings.state_dir.resolve()}
        paths = path.rglob("*") if path.is_dir() else [path]
        for item in paths:
            try:
                resolved = item.resolve()
                if any(resolved == root or resolved.is_relative_to(root) for root in excluded_roots):
                    details["skipped"].append(str(item))  # type: ignore[index]
                    continue
                arcname = str(item).lstrip("/")
                tar.add(item, arcname=arcname, recursive=False)
                details["included"].append(str(item))  # type: ignore[index]
            except (OSError, PermissionError) as exc:
                details["skipped"].append(f"{item}: {exc}")  # type: ignore[index]


def default_triage_paths() -> list[Path]:
    return [
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
        Path("/var/log/syslog"),
        Path("/var/log/messages"),
        Path("/var/log/audit"),
        Path("/etc/passwd"),
        Path("/etc/group"),
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/tmp"),
    ]


def cron_paths(root: Path) -> list[Path]:
    return [
        root / "crontab",
        root / "cron.d",
        root / "cron.daily",
        root / "cron.hourly",
        root / "cron.monthly",
        root / "cron.weekly",
    ]


def _safe_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value)
    return safe.strip(".-") or "default"
