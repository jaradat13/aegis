from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Suggestion:
    title: str
    rationale: str
    command: str


def suggest_response(indicator: str, context: str = "") -> list[Suggestion]:
    text = f"{indicator} {context}".lower()
    suggestions: list[Suggestion] = []
    if any(term in text for term in ["reverse shell", "beacon", "c2", "malware", "unknown process"]):
        suggestions.append(
            Suggestion(
                "Contain suspicious process",
                "Process indicators suggest active execution or command-and-control behavior.",
                "aegis-ir kill-process <pid> --reason 'suspected malicious execution' --execute",
            )
        )
    if any(term in text for term in ["exfil", "lateral", "scan", "network", "beacon", "c2"]):
        suggestions.append(
            Suggestion(
                "Isolate network path",
                "Network indicators suggest containment may reduce blast radius.",
                "aegis-ir isolate-interface <iface> --reason 'incident containment' --execute",
            )
        )
    if any(term in text for term in ["cron", "persistence", "scheduled task"]):
        suggestions.append(
            Suggestion(
                "Roll back cron persistence",
                "Scheduled task changes are a common persistence mechanism.",
                "aegis-ir rollback-cron known-good --execute",
            )
        )
    suggestions.append(
        Suggestion(
            "Collect triage package",
            "Capture volatile investigative context before broad remediation.",
            "aegis-ir collect-triage INC-001 --execute",
        )
    )
    return suggestions

