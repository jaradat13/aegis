from __future__ import annotations

import argparse
from pathlib import Path

from .actions import ResponseOrchestrator
from .audit import AuditLog
from .config import get_settings
from .llm import suggest_response


def _orchestrator(state_dir: Path | None) -> ResponseOrchestrator:
    settings = get_settings(state_dir)
    return ResponseOrchestrator(settings)


def _print_result(result) -> None:
    print(f"{result.action} {result.target}: {result.status}")
    for key, value in result.details.items():
        print(f"  {key}: {value}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis-ir", description="Offline-first incident response orchestrator.")
    parser.add_argument("--state-dir", type=Path, default=None, help="Override local state directory.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    kill = subparsers.add_parser("kill-process", help="Kill a suspicious process.")
    kill.add_argument("pid", type=int)
    kill.add_argument("--reason", required=True)
    kill.add_argument("--execute", action="store_true", help="Perform the action. Defaults to dry-run.")

    isolate = subparsers.add_parser("isolate-interface", help="Set a network interface down.")
    isolate.add_argument("interface")
    isolate.add_argument("--reason", required=True)
    isolate.add_argument("--execute", action="store_true", help="Perform the action. Defaults to dry-run.")

    triage = subparsers.add_parser("collect-triage", help="Create a forensic triage tarball.")
    triage.add_argument("incident_id")
    triage.add_argument("--path", "-p", action="append", type=Path, default=[])
    triage.add_argument("--execute", action="store_true", help="Create the package. Defaults to dry-run.")

    baseline = subparsers.add_parser("save-cron-baseline", help="Snapshot cron files.")
    baseline.add_argument("name")
    baseline.add_argument("--source", type=Path, default=None, help="Cron root to snapshot. Defaults to /etc.")

    rollback = subparsers.add_parser("rollback-cron", help="Restore cron from a known-good baseline.")
    rollback.add_argument("baseline")
    rollback.add_argument("--destination-root", type=Path, default=None, help="Restore destination. Defaults to /etc.")
    rollback.add_argument("--execute", action="store_true", help="Restore files. Defaults to dry-run.")

    verify = subparsers.add_parser("audit-verify", help="Verify audit signatures and hash chain.")
    _ = verify

    tail = subparsers.add_parser("audit-tail", help="Show recent audit entries.")
    tail.add_argument("--limit", type=int, default=10)

    suggest = subparsers.add_parser("suggest", help="Generate offline response suggestions.")
    suggest.add_argument("indicator")
    suggest.add_argument("--context", default="")

    dashboard = subparsers.add_parser("dashboard", help="Run the local web dashboard.")
    dashboard.add_argument("--host", default=None)
    dashboard.add_argument("--port", type=int, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "kill-process":
        orch = _orchestrator(args.state_dir)
        _print_result(orch.kill_process(args.pid, reason=args.reason, dry_run=not args.execute))
    elif args.command == "isolate-interface":
        orch = _orchestrator(args.state_dir)
        _print_result(orch.isolate_interface(args.interface, reason=args.reason, dry_run=not args.execute))
    elif args.command == "collect-triage":
        orch = _orchestrator(args.state_dir)
        _print_result(orch.collect_triage(args.incident_id, paths=args.path or None, dry_run=not args.execute))
    elif args.command == "save-cron-baseline":
        orch = _orchestrator(args.state_dir)
        target = orch.save_cron_baseline(args.name, source=args.source)
        print(f"Saved cron baseline to {target}")
    elif args.command == "rollback-cron":
        orch = _orchestrator(args.state_dir)
        _print_result(orch.rollback_cron(args.baseline, destination_root=args.destination_root, dry_run=not args.execute))
    elif args.command == "audit-verify":
        ok, errors = AuditLog(get_settings(args.state_dir)).verify()
        if ok:
            print("Audit log verified")
            return 0
        for error in errors:
            print(error)
        return 1
    elif args.command == "audit-tail":
        for entry in AuditLog(get_settings(args.state_dir)).entries(limit=max(args.limit, 1)):
            print(entry)
    elif args.command == "suggest":
        for item in suggest_response(args.indicator, args.context):
            print(f"{item.title}: {item.rationale}")
            print(f"  {item.command}")
    elif args.command == "dashboard":
        from .web import serve

        settings = get_settings(args.state_dir)
        serve(settings, args.host or settings.dashboard_host, args.port or settings.dashboard_port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
