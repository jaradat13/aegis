# Aegis IR

Offline-first incident response orchestrator for air-gapped SOCs and lab environments. It provides a dependency-free Python CLI and a local web dashboard for containment, forensic triage, cron rollback, signed audit logging, and offline response suggestions.

## Capabilities

- Kill suspicious processes with signed audit records.
- Isolate network interfaces with `ip link set <iface> down`.
- Collect forensic triage tarballs from logs, configs, binaries, and operator-selected paths.
- Snapshot cron configuration and roll back to a known-good baseline.
- Append-only JSONL audit log with HMAC signatures and hash chaining.
- Offline LLM-style suggestions from local rules, with no network dependency.
- Dry-run by default for disruptive actions.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

The app uses only Python standard-library modules at runtime, so it can also run directly from a checkout:

```bash
python -m aegis_ir.cli --help
```

## CLI

All state is stored under `~/.local/state/aegis-ir` by default. Override it with `--state-dir` or `AEGIS_IR_STATE`.

```bash
aegis-ir kill-process 4242 --reason "unknown binary beaconing"
aegis-ir kill-process 4242 --reason "confirmed malicious process" --execute

aegis-ir isolate-interface eth0 --reason "contain C2 traffic"
aegis-ir isolate-interface eth0 --reason "contain C2 traffic" --execute

aegis-ir collect-triage INC-2026-001 --path /var/log --path /tmp/suspicious.bin --execute

aegis-ir save-cron-baseline known-good
aegis-ir rollback-cron known-good
aegis-ir rollback-cron known-good --execute

aegis-ir suggest "cron persistence and C2 beacon"
aegis-ir audit-verify
aegis-ir audit-tail --limit 20
```

## Dashboard

```bash
python -m aegis_ir.cli dashboard --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`. The dashboard exposes the same workflow as the CLI and shows recent signed audit entries.

## Safety Model

Containment actions are dry-run unless `--execute` is passed or the dashboard Execute checkbox is selected. Executed process kills and network isolation require appropriate OS permissions. Cron rollback defaults to `/etc`, so production use should be restricted to trusted operators.

## Forensic Triage

Default triage collection attempts to include common Linux incident response artifacts:

- `/var/log/auth.log`
- `/var/log/secure`
- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/audit`
- `/etc/passwd`
- `/etc/group`
- `/etc/crontab`
- `/etc/cron.d`
- `/tmp`

Missing paths are recorded in the audit details and do not fail the collection.

## Audit Integrity

Each action writes a JSONL audit entry containing timestamp, actor, action, target, details, previous entry hash, HMAC signature, and entry hash. `aegis-ir audit-verify` validates signatures and chain continuity.

The signing key is generated locally at first run in `audit.key` with mode `0600`.

## Tests

```bash
python -m unittest discover -s tests
```
