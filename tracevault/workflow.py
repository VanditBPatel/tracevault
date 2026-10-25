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


COLLECTION_MANIFEST = "manifest.json"


def ingest_collection(case: Case, folder: Path, examiner: str | None = None) -> dict[str, Any]:
    """Ingest a collector output folder. Every file is checked against the SHA-256 the collector
    recorded on the host; if anything is missing or altered, nothing is ingested."""
    examiner = examiner or default_examiner()
    folder = Path(folder)
    manifest_path = folder / COLLECTION_MANIFEST
    if not manifest_path.is_file():
        raise ValueError(f"No {COLLECTION_MANIFEST} in {folder} - is this a TraceVault collector folder?")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if "TraceVault" not in str(manifest.get("collector", "")) or not isinstance(manifest.get("files"), list):
        raise ValueError(f"{manifest_path} is not a TraceVault collector manifest")

    problems, verified = [], []
    for entry in manifest["files"]:
        name = str(entry.get("name", ""))
        if not name or Path(name).name != name:  # plain file names only, nothing that walks out of the folder
            problems.append(f"invalid file name in manifest: {name!r}")
            continue
        path = folder / name
        if not path.is_file():
            problems.append(f"{name}: listed in the manifest but missing")
            continue
        actual = sha256_file(path)
        if actual != str(entry.get("sha256", "")).lower():
            problems.append(f"{name}: SHA-256 differs from the collector's ({actual[:16]}... vs {str(entry.get('sha256'))[:16]}...)")
            continue
        verified.append((path, entry))
    if problems:
        raise IOError("Collection failed verification - nothing was ingested:\n  " + "\n  ".join(problems))

    listed = {p.name for p, _ in verified} | {COLLECTION_MANIFEST}
    unlisted = sorted(p.name for p in folder.iterdir() if p.is_file() and p.name not in listed)

    source = f"collected on {manifest.get('host')} by {manifest.get('collected_by_account')}"
    case.ingest(manifest_path, examiner=examiner, note=f"collector manifest, {source}")
    for path, entry in verified:
        case.ingest(path, examiner=examiner,
                    note=f"{entry.get('channel')} ({entry.get('events')} events), {source}, verified against manifest")
    window = manifest.get("window") or {}
    return case.log("evidence.collection", examiner, details={
        "collector": manifest.get("collector"),
        "collector_version": manifest.get("version"),
        "host": manifest.get("host"),
        "collected_by_account": manifest.get("collected_by_account"),
        "collector_examiner": manifest.get("examiner"),
        "elevated": manifest.get("elevated"),
        "window": window,
        "collected_at": manifest.get("finished_at"),
        "manifest_sha256": sha256_file(manifest_path),
        "files": [{"name": e.get("name"), "channel": e.get("channel"), "events": e.get("events"),
                   "sha256": e.get("sha256")} for _, e in verified],
        "skipped": manifest.get("skipped", []),
        "unlisted_files_not_ingested": unlisted,
    })


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
