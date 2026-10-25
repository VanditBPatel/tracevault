"""Turn events + findings into a case analysis: risk score, ATT&CK chain, IOCs and a narrative.

The narrative is template-driven and built only from findings, so every sentence traces back
to specific evidence events - no generated text that cannot be verified.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from . import __version__, detections, identities, suppressions
from .models import SEVERITY_ORDER, Event, Finding

ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]

# Probability-style weights: how strongly one kind of malicious behaviour (one rule) indicates
# compromise. Distinct behaviours combine as independent evidence.
SEVERITY_WEIGHT = {"low": 0.05, "medium": 0.15, "high": 0.30, "critical": 0.50}
# More findings of the SAME rule add only a little: +25% of the rule's weight for each of the
# next two, nothing after that. Ten installs of ten agents are not ten attacks.
REPEAT_BONUS, REPEAT_CAP = 0.25, 2


def risk_assessment(findings: list[Finding]) -> dict[str, Any]:
    """Score how strongly the evidence indicates compromise, with the reasons for the score.

    The unit of evidence is a distinct behaviour (detection rule), not an alert: repeated
    findings of one rule barely move the score, while different behaviours - especially across
    several ATT&CK tactics - compound.
    """
    if not findings:
        return {"score": 0, "level": "low", "reasons": ["No attacker activity was detected."], "contributors": []}
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    contributors = []
    remaining = 1.0
    for rule_id, fs in by_rule.items():
        top = max(fs, key=lambda f: SEVERITY_ORDER.get(f.severity, 0))
        w = SEVERITY_WEIGHT.get(top.severity, 0)
        c = min(0.95, w * (1 + REPEAT_BONUS * min(len(fs) - 1, REPEAT_CAP)))
        remaining *= 1 - c
        contributors.append({"rule_id": rule_id, "title": top.title, "severity": top.severity,
                             "findings": len(fs), "points": round(100 * c)})
    contributors.sort(key=lambda x: (-x["points"], x["rule_id"]))
    score = round(100 * (1 - remaining))

    sev = Counter(f.severity for f in findings)
    tactics = sorted({f.tactic for f in findings}, key=ATTACK_TACTICS.index)
    mix = ", ".join(f"{sev[s]} {s}" for s in ("critical", "high", "medium", "low") if sev[s])
    reasons = [f"{len(by_rule)} distinct suspicious behaviour{'s' if len(by_rule) != 1 else ''} "
               f"({len(findings)} finding{'s' if len(findings) != 1 else ''}: {mix}) across "
               f"{len(tactics)} ATT&CK tactic{'s' if len(tactics) != 1 else ''}."]
    if len(findings) > len(by_rule):
        reasons.append(f"Repeats of the same behaviour add little: {len(findings)} findings come from "
                       f"{len(by_rule)} rule{'s' if len(by_rule) != 1 else ''}.")
    if len(tactics) >= 3:
        reasons.append(f"The activity forms a chain from {tactics[0]} to {tactics[-1]}.")
    elif not sev["critical"]:
        reasons.append("No critical finding and no multi-stage chain: treat as signals to review, "
                       "not a confirmed intrusion.")
    reasons.append("Biggest contributors: " + "; ".join(
        f"{c['title']} ({c['severity']}{', x' + str(c['findings']) if c['findings'] > 1 else ''})"
        for c in contributors[:3]) + ".")
    return {"score": score, "level": risk_level(score), "reasons": reasons, "contributors": contributors}


def risk_score(findings: list[Finding]) -> int:
    return risk_assessment(findings)["score"]


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
    """Indicators from attacker-attributed evidence only (context events are excluded)."""
    ips: Counter = Counter()
    users: Counter = Counter()
    hosts: Counter = Counter()
    for f in findings:
        attributed = f.attributed()
        ips.update(f.attributed_ips())
        users.update({e.user for e in attributed if e.user})
        hosts.update({e.host for e in attributed if e.host})
    return {
        "ips": [{"value": ip, "findings": n, "external": _is_external(ip)} for ip, n in ips.most_common()],
        "users": [{"value": u, "findings": n} for u, n in users.most_common()],
        "hosts": [{"value": h, "findings": n} for h, n in hosts.most_common()],
    }


def narrative(findings: list[Finding], idents: list[dict[str, Any]] | None = None) -> list[str]:
    """An identity summary, then one plain-English line per tactic observed, in kill-chain order."""
    if not findings:
        return ["No attacker activity detected in the supplied evidence."]
    lines = []
    for status, label in (("compromised", "Compromised identities"), ("created", "Accounts created by the attacker")):
        hits = [i for i in idents or [] if i["status"] == status]
        if hits:
            lines.append(f"{label}: " + "; ".join(
                f"{i['identity']} ({', '.join(i['systems'])})" for i in hits) + ".")
    for tactic in ATTACK_TACTICS:
        hits = [f for f in findings if f.tactic == tactic]
        if not hits:
            continue
        first = min(hits, key=lambda f: f.ts)
        titles = sorted({f.title for f in hits}, key=str.lower)
        hosts = sorted({h for f in hits for h in f.entities()["hosts"]})
        lines.append(
            f"{tactic} - from {first.ts:%H:%M} UTC: {'; '.join(titles)} on {', '.join(hosts)} "
            f"({len(hits)} finding{'s' if len(hits) != 1 else ''})."
        )
    return lines


def analyze(events: list[Event], rules: list[dict] | None = None, case: dict | None = None,
            identity_map: dict[str, str] | None = None,
            active_suppressions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    findings = detections.run(events, rules)
    # Analyst-reviewed findings are kept in the output (with who/why) but drop out of everything
    # that describes the attack.
    suppressed = suppressions.apply(findings, active_suppressions or [])
    live = [f for i, f in enumerate(findings) if i not in suppressed]

    flagged: dict[str, list[str]] = {}
    for f in live:
        for e in f.events:
            flagged.setdefault(e.id, []).append(f.rule_id)

    # Posture findings (risky practice) are reported but do not drive the attack story,
    # the risk score, the IOCs or the attacker window.
    attack = [f for f in live if f.category == "attack"]
    posture = [f for f in live if f.category != "attack"]
    idents = identities.build(attack, identity_map)

    risk = risk_assessment(attack)
    sev_counts = Counter(f.severity for f in attack)
    attributed_ids = {e.id for f in attack for e in f.attributed()}
    malicious = [e for e in events if e.id in attributed_ids]

    return {
        "tool": {"name": "TraceVault", "version": __version__},
        "case": case or {},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk": risk,
        "stats": {
            "events": len(events),
            "flagged_events": len(flagged),
            "findings": len(attack),
            "posture_findings": len(posture),
            "suppressed_findings": len(suppressed),
            "identities_compromised": sum(i["status"] == "compromised" for i in idents),
            "by_severity": {s: sev_counts.get(s, 0) for s in SEVERITY_ORDER},
            "by_source": dict(Counter(e.source for e in events)),
            "by_kind": dict(Counter(e.kind for e in events).most_common()),
            "time_range": [events[0].ts.isoformat(), events[-1].ts.isoformat()] if events else None,
            "dwell": [malicious[0].ts.isoformat(), malicious[-1].ts.isoformat()] if malicious else None,
        },
        "narrative": narrative(attack, idents),
        "attack_chain": attack_chain(attack),
        "iocs": iocs(attack),
        "identities": idents,
        "findings": [
            {**f.to_dict(),
             "attributed_fps": sorted({e.fingerprint() for e in f.attributed()}),
             "suppressed": _suppression_ref(suppressed.get(i))}
            for i, f in enumerate(findings)
        ],
        # The full super-timeline, each event tagged with the (unsuppressed) rules it contributed to.
        "timeline": [{**e.to_dict(), "rules": flagged.get(e.id, [])} for e in events],
    }


def _suppression_ref(s: dict[str, Any] | None) -> dict[str, Any] | None:
    if not s:
        return None
    return {"id": s["id"], "verdict": s["verdict"], "reason": s["reason"], "by": s["by"], "at": s["at"],
            "scope": suppressions.describe(s)}


def summary(result: dict[str, Any]) -> dict[str, Any]:
    """The few numbers the case list needs, so it never has to load a large analysis.json."""
    return {
        "generated_at": result["generated_at"],
        "risk": result["risk"],
        "findings": result["stats"]["findings"],
        "posture_findings": result["stats"]["posture_findings"],
        "suppressed_findings": result["stats"]["suppressed_findings"],
        "events": result["stats"]["events"],
    }
