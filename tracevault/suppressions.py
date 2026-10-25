"""Analyst tuning: suppress findings an analyst has reviewed, with the decision on the record.

Suppressions are not a side file. Each one is a `finding.suppress` entry in the case's
hash-chained custody ledger, and is withdrawn by a `finding.unsuppress` entry. The active set is
rebuilt by replaying the ledger, so who suppressed what, when and why is tamper-evident and
appears in the report.

A suppression applies to one rule and has one of two scopes:
  finding  exactly the finding with these event fingerprints (stable across re-analysis)
  where    every finding of the rule with an attributed event matching all the conditions,
           e.g. source_image equals C:\\WindowsAzure\\...\\CollectGuestLogs.exe

Verdicts: false_positive (the rule was wrong) or expected_activity (the rule was right, but the
activity was authorized - an admin task, a pentest).
"""

from __future__ import annotations

import re
from typing import Any

from .models import Finding

VERDICTS = ("false_positive", "expected_activity")
RULE_ID_RE = re.compile(r"^TV-\d{3}$")
FIELD_RE = re.compile(r"^[a-z_]{1,40}$")
MAX_TEXT = 2000


def validate_request(req: dict[str, Any]) -> dict[str, Any]:
    """Check an incoming suppression and return the normalized details to log."""
    rule_id = str(req.get("rule_id", ""))
    if not RULE_ID_RE.match(rule_id):
        raise ValueError("rule_id must look like TV-030")
    verdict = req.get("verdict", "false_positive")
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {', '.join(VERDICTS)}")
    reason = str(req.get("reason", "")).strip()
    if len(reason) < 5:
        raise ValueError("a reason of at least 5 characters is required")
    if len(reason) > MAX_TEXT:
        raise ValueError("reason is too long")

    scope = req.get("scope")
    details: dict[str, Any] = {"rule_id": rule_id, "verdict": verdict, "reason": reason, "scope": scope}
    if scope == "finding":
        fps = [str(f) for f in req.get("fingerprints") or []]
        if not fps or not all(re.fullmatch(r"[0-9a-f]{16}", f) for f in fps):
            raise ValueError("scope 'finding' needs the finding's event fingerprints")
        details["fingerprints"] = sorted(set(fps))
    elif scope == "where":
        conditions = []
        for c in req.get("conditions") or []:
            field, op, value = str(c.get("field", "")), c.get("op", "equals"), str(c.get("value", ""))
            if not FIELD_RE.match(field) or op not in ("equals", "regex") or not value or len(value) > MAX_TEXT:
                raise ValueError(f"invalid condition {c!r}")
            if op == "regex":
                re.compile(value)
            conditions.append({"field": field, "op": op, "value": value})
        if not conditions:
            raise ValueError("scope 'where' needs at least one condition")
        details["conditions"] = conditions
    else:
        raise ValueError("scope must be 'finding' or 'where'")
    return details


def replay(entries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Rebuild (active, revoked) suppressions from the custody ledger."""
    active: dict[str, dict[str, Any]] = {}
    revoked: list[dict[str, Any]] = []
    for e in entries:
        d = e.get("details") or {}
        if e.get("action") == "finding.suppress":
            active[d["id"]] = {**d, "by": e["actor"], "at": e["ts"], "seq": e["seq"]}
        elif e.get("action") == "finding.unsuppress" and d.get("id") in active:
            s = active.pop(d["id"])
            revoked.append({**s, "revoked_by": e["actor"], "revoked_at": e["ts"],
                            "revoke_reason": d.get("reason", "")})
    return list(active.values()), revoked


def next_id(entries: list[dict[str, Any]]) -> str:
    n = sum(1 for e in entries if e.get("action") == "finding.suppress")
    return f"S{n + 1}"


def describe(s: dict[str, Any]) -> str:
    if s["scope"] == "finding":
        return f"{s['rule_id']}: this finding only ({len(s['fingerprints'])} events)"
    parts = [f"{c['field']} {'=' if c['op'] == 'equals' else '~'} {c['value']}" for c in s["conditions"]]
    return f"{s['rule_id']} where " + " and ".join(parts)


def _cond_ok(event, cond: dict[str, str]) -> bool:
    actual = event.get(cond["field"])
    if actual is None:
        return False
    if cond["op"] == "equals":
        return str(actual).strip().lower() == cond["value"].strip().lower()
    return bool(re.search(cond["value"], str(actual), re.IGNORECASE))


def matches(finding: Finding, s: dict[str, Any]) -> bool:
    if s["rule_id"] != finding.rule_id:
        return False
    attributed = finding.attributed()
    if s["scope"] == "finding":
        return {e.fingerprint() for e in attributed} == set(s["fingerprints"])
    return any(all(_cond_ok(e, c) for c in s["conditions"]) for e in attributed)


def apply(findings: list[Finding], active: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """Map finding index -> the (first) suppression that covers it."""
    out: dict[int, dict[str, Any]] = {}
    for i, f in enumerate(findings):
        hit = next((s for s in active if matches(f, s)), None)
        if hit:
            out[i] = hit
    return out
