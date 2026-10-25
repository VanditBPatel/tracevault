"""High-level case operations shared by the CLI and the web server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import analysis, detections, identities, parsers, report
from .custody import Case, default_examiner, sha256_file

IDENTITY_MAP = "identities.json"


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
    result = analysis.analyze(events, detections.load_rules(rules_path), case=meta,
                              identity_map=identities.load_map(map_path))

    (case.dir / "analysis.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    case.log("analysis.run", examiner, details={
        "events": result["stats"]["events"],
        "findings": result["stats"]["findings"],
        "posture_findings": result["stats"]["posture_findings"],
        "risk_score": result["risk"]["score"],
        "identity_map_sha256": sha256_file(map_path) if map_path.exists() else None,
    })
    export_report(case, result, examiner)
    return result


def export_report(case: Case, result: dict[str, Any], examiner: str | None = None) -> Path:
    path = case.dir / "report.html"
    path.write_text(report.render(result, case.entries(), case.verify()), encoding="utf-8")
    case.log("report.export", examiner or default_examiner(), evidence=None,
             details={"file": path.name})
    return path


def load_analysis(case: Case) -> dict[str, Any] | None:
    path = case.dir / "analysis.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
