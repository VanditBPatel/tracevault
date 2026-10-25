"""Turn events + findings into a case analysis: risk score, ATT&CK chain, IOCs and a narrative.

The narrative is template-driven and built only from findings, so every sentence traces back
to specific evidence events - no generated text that cannot be verified.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from . import __version__, detections
from .models import SEVERITY_ORDER, Event, Finding

ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]

# Probability-style weights: each finding independently "adds" this much risk.
SEVERITY_WEIGHT = {"low": 0.05, "medium": 0.15, "high": 0.30, "critical": 0.50}


def risk_score(findings: list[Finding]) -> int:
    remaining = 1.0
    for f in findings:
        remaining *= 1 - SEVERITY_WEIGHT.get(f.severity, 0)
    return round(100 * (1 - remaining))


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _is_external(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not detections.is_internal_ip(ip)


def attack_chain(findings: list[Finding]) -> list[dict[str, Any]]:
    chain = []
    for tactic in ATTACK_TACTICS:
        hits = [f for f in findings if f.tactic == tactic]
        techniques = sorted({(f.technique, f.technique_name) for f in hits})
        chain.append({
            "tactic": tactic,
            "count": len(hits),
            "max_severity": max((f.severity for f in hits), key=SEVERITY_ORDER.get, default=None),
            "techniques": [{"id": t, "name": n} for t, n in techniques],
        })
    return chain


def iocs(findings: list[Finding]) -> dict[str, list[dict[str, Any]]]:
    ips: Counter = Counter()
    users: Counter = Counter()
    hosts: Counter = Counter()
    for f in findings:
        ents = f.entities()
        ips.update(ents["ips"])
        users.update(ents["users"])
        hosts.update(ents["hosts"])
    return {
        "ips": [{"value": ip, "findings": n, "external": _is_external(ip)} for ip, n in ips.most_common()],
        "users": [{"value": u, "findings": n} for u, n in users.most_common()],
        "hosts": [{"value": h, "findings": n} for h, n in hosts.most_common()],
    }


def narrative(findings: list[Finding]) -> list[str]:
    """One plain-English line per tactic observed, in kill-chain order."""
    if not findings:
        return ["No detection rules fired on the supplied evidence."]
    lines = []
    for tactic in ATTACK_TACTICS:
        hits = [f for f in findings if f.tactic == tactic]
        if not hits:
            continue
        first = min(hits, key=lambda f: f.ts)
        titles = sorted({f.title.lower() for f in hits})
        hosts = sorted({h for f in hits for h in f.entities()["hosts"]})
        lines.append(
            f"{tactic} - from {first.ts:%H:%M} UTC: {'; '.join(titles)} on {', '.join(hosts)} "
            f"({len(hits)} finding{'s' if len(hits) != 1 else ''})."
        )
    return lines


def analyze(events: list[Event], rules: list[dict] | None = None, case: dict | None = None) -> dict[str, Any]:
    findings = detections.run(events, rules)
    flagged: dict[str, list[str]] = {}
    for f in findings:
        for e in f.events:
            flagged.setdefault(e.id, []).append(f.rule_id)

    score = risk_score(findings)
    sev_counts = Counter(f.severity for f in findings)
    malicious = [e for e in events if e.id in flagged]

    return {
        "tool": {"name": "TraceVault", "version": __version__},
        "case": case or {},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk": {"score": score, "level": risk_level(score)},
        "stats": {
            "events": len(events),
            "flagged_events": len(malicious),
            "findings": len(findings),
            "by_severity": {s: sev_counts.get(s, 0) for s in SEVERITY_ORDER},
            "by_source": dict(Counter(e.source for e in events)),
            "by_kind": dict(Counter(e.kind for e in events).most_common()),
            "time_range": [events[0].ts.isoformat(), events[-1].ts.isoformat()] if events else None,
            "dwell": [malicious[0].ts.isoformat(), malicious[-1].ts.isoformat()] if malicious else None,
        },
        "narrative": narrative(findings),
        "attack_chain": attack_chain(findings),
        "iocs": iocs(findings),
        "findings": [f.to_dict() for f in findings],
        # The full super-timeline, each event tagged with the rules it contributed to.
        "timeline": [{**e.to_dict(), "rules": flagged.get(e.id, [])} for e in events],
    }
