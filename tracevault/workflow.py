"""High-level case operations shared by the CLI and the web server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import analysis, detections, identities, parsers, report, suppressions
from .custody import Case, default_examiner, sha256_file

IDENTITY_MAP = "identities.json"
SUMMARY = "summary.json"


def analyze_case(case: Case, examiner: str | None = None, year: int | None = None,
                 rules_path: Path | None = None) -> dict[str, Any]:
    """Parse all evidence in a case, run detections, write analysis.json + report.html, log it."""
    examiner = examiner or default_examiner()
    meta = case.meta
    # Classic syslog lines carry no year; assume the year the case was opened.
    year = year or int(meta["created_at"][:4])

    events = parsers.parse_files(case.evidence_files(), year=year)
    # Analyst-maintained identity map; its hash goes in the ledger so the linking used
    # for this analysis is on record.
    map_path = case.dir / IDENTITY_MAP
    active, _ = suppressions.replay(case.entries())
    result = analysis.analyze(events, detections.load_rules(rules_path), case=meta,
                              identity_map=identities.load_map(map_path), active_suppressions=active)

    # Compact JSON: this file holds the whole timeline and can be tens of MB.
    (case.dir / "analysis.json").write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
    (case.dir / SUMMARY).write_text(json.dumps(analysis.summary(result), indent=2), encoding="utf-8")
    case.log("analysis.run", examiner, details={
        "events": result["stats"]["events"],
        "findings": result["stats"]["findings"],
        "posture_findings": result["stats"]["posture_findings"],
        "suppressed_findings": result["stats"]["suppressed_findings"],
        "active_suppressions": [s["id"] for s in active],
        "risk_score": result["risk"]["score"],
        "identity_map_sha256": sha256_file(map_path) if map_path.exists() else None,
    })
    export_report(case, result, examiner)
    return result


def export_report(case: Case, result: dict[str, Any], examiner: str | None = None) -> Path:
    path = case.dir / "report.html"
    active, revoked = suppressions.replay(case.entries())
    path.write_text(report.render(result, case.entries(), case.verify(), revoked), encoding="utf-8")
    case.log("report.export", examiner or default_examiner(), evidence=None,
             details={"file": path.name})
    return path


def suppress(case: Case, request: dict[str, Any], examiner: str | None = None,
             reanalyze: bool = True) -> dict[str, Any]:
    """Record an analyst's suppression in the custody ledger, then re-run the analysis."""
    details = suppressions.validate_request(request)
    details["id"] = suppressions.next_id(case.entries())
    entry = case.log("finding.suppress", examiner or default_examiner(), details=details)
    if reanalyze:
        analyze_case(case, examiner=examiner)
    return entry


def unsuppress(case: Case, suppression_id: str, reason: str, examiner: str | None = None,
               reanalyze: bool = True) -> dict[str, Any]:
    active, _ = suppressions.replay(case.entries())
    if suppression_id not in {s["id"] for s in active}:
        raise ValueError(f"No active suppression {suppression_id}")
    if len(reason.strip()) < 5:
        raise ValueError("a reason of at least 5 characters is required")
    entry = case.log("finding.unsuppress", examiner or default_examiner(),
                     details={"id": suppression_id, "reason": reason.strip()})
    if reanalyze:
        analyze_case(case, examiner=examiner)
    return entry


def load_analysis(case: Case) -> dict[str, Any] | None:
    path = case.dir / "analysis.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def load_summary(case: Case) -> dict[str, Any] | None:
    """Small per-case summary; rebuilt once from analysis.json for cases analysed before it existed."""
    path = case.dir / SUMMARY
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    result = load_analysis(case)
    if result is None:
        return None
    result["stats"].setdefault("suppressed_findings", 0)
    result["stats"].setdefault("posture_findings", 0)
    data = analysis.summary(result)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data
