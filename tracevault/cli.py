"""Command-line interface:  tracevault <command> ...  (or python -m tracevault)"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, analysis, detections, identities, parsers, workflow
from .custody import Case

SAMPLES = Path(__file__).resolve().parent / "samples"
SAMPLE_CASES = {
    "CASE-001": ("case-001", "Acme Labs - web server and finance workstation compromise"),
    "CASE-002": ("case-002", "Acme Labs - cloud identity takeover (Okta, Microsoft 365, AWS)"),
}
SEV_TAG = {"low": "LOW ", "medium": "MED ", "high": "HIGH", "critical": "CRIT"}


def _print_summary(result: dict) -> None:
    s, r = result["stats"], result["risk"]
    print(f"\n  Risk score  {r['score']}/100 ({r['level'].upper()})")
    print(f"  Events      {s['events']} analysed, {s['flagged_events']} flagged")
    print(f"  Findings    {s['findings']}  " + "  ".join(f"{k}={v}" for k, v in s["by_severity"].items())
          + f"   (+{s['posture_findings']} posture, {s.get('suppressed_findings', 0)} suppressed)")
    print("\n  Storyline")
    for line in result["narrative"]:
        print(f"   - {line}")
    if result["identities"]:
        print("\n  Identities")
        for i in result["identities"]:
            aliases = f"  aliases: {', '.join(i['aliases'])}" if len(i["aliases"]) > 1 else ""
            print(f"   {i['status']:<11} {i['identity']:<20} {', '.join(i['systems'])}{aliases}")
    for category, label in (("attack", "Findings"), ("posture", "Security posture")):
        rows = [f for f in result["findings"] if f["category"] == category and not f.get("suppressed")]
        if rows:
            print(f"\n  {label}")
        for f in rows:
            print(f"   [{SEV_TAG[f['severity']]}] {f['ts'][11:19]} {f['rule_id']} {f['technique']:<10} {f['title']}")
    print()


def cmd_case_new(a: argparse.Namespace) -> int:
    case = Case.create(a.cases, a.case_id, title=a.title, examiner=a.examiner)
    print(f"Created case {case.id} at {case.dir}")
    return 0


def cmd_ingest(a: argparse.Namespace) -> int:
    case = Case.open(a.cases, a.case_id)
    for f in a.files:
        entry = case.ingest(Path(f), examiner=a.examiner, note=a.note)
        print(f"  + {entry['evidence']:<32} sha256={entry['sha256']}")
    return 0


def cmd_analyze(a: argparse.Namespace) -> int:
    case = Case.open(a.cases, a.case_id)
    result = workflow.analyze_case(case, examiner=a.examiner, year=a.year,
                                   rules_path=Path(a.rules) if a.rules else None)
    _print_summary(result)
    print(f"  Report: {case.dir / 'report.html'}")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    v = Case.open(a.cases, a.case_id).verify()
    print(f"Ledger entries: {v['entries']}   head: {v['head']}")
    for ev in v["evidence"]:
        print(f"  {'OK ' if ev['ok'] else 'BAD'} {ev['file']}")
    if v["ok"]:
        print("INTEGRITY VERIFIED")
        return 0
    print("INTEGRITY FAILURE:")
    for p in v["problems"]:
        print(f"  ! {p}")
    return 2


def cmd_anchor(a: argparse.Namespace) -> int:
    print(json.dumps(Case.open(a.cases, a.case_id).anchor(), indent=2))
    return 0


def cmd_scan(a: argparse.Namespace) -> int:
    """Quick triage of loose files without opening a case (no custody record)."""
    events = parsers.parse_files([Path(f) for f in a.files], year=a.year)
    result = analysis.analyze(events, detections.load_rules(Path(a.rules) if a.rules else None),
                              identity_map=identities.load_map(Path(a.identities) if a.identities else None))
    if a.json:
        json.dump(result, sys.stdout, indent=2)
    else:
        _print_summary(result)
    return 1 if result["stats"]["findings"] else 0


def _conditions(pairs: list[str], op: str) -> list[dict[str, str]]:
    out = []
    for pair in pairs or []:
        field, sep, value = pair.partition("=")
        if not sep:
            raise ValueError(f"expected field=value, got {pair!r}")
        out.append({"field": field.strip(), "op": op, "value": value})
    return out


def cmd_suppress(a: argparse.Namespace) -> int:
    case = Case.open(a.cases, a.case_id)
    request: dict = {"rule_id": a.rule, "verdict": a.verdict, "reason": a.reason}
    if a.finding:
        analysis_ = workflow.load_analysis(case) or {}
        match = [f for f in analysis_.get("findings", []) if a.finding in f["event_ids"] and f["rule_id"] == a.rule]
        if not match:
            raise ValueError(f"no {a.rule} finding contains event {a.finding}")
        request.update(scope="finding", fingerprints=match[0]["attributed_fps"])
    else:
        request.update(scope="where", conditions=_conditions(a.where, "equals") + _conditions(a.where_regex, "regex"))
    entry = workflow.suppress(case, request, examiner=a.examiner)
    print(f"Recorded {entry['details']['id']} in the custody ledger (entry {entry['seq']}) and re-ran analysis.")
    return 0


def cmd_suppressions(a: argparse.Namespace) -> int:
    from . import suppressions
    active, revoked = suppressions.replay(Case.open(a.cases, a.case_id).entries())
    for s in active:
        print(f"  {s['id']:<4} {s['verdict']:<18} {suppressions.describe(s)}\n       by {s['by']} at {s['at']}: {s['reason']}")
    for s in revoked:
        print(f"  {s['id']:<4} WITHDRAWN          {suppressions.describe(s)}\n       by {s['revoked_by']}: {s['revoke_reason']}")
    if not active and not revoked:
        print("  No suppressions.")
    return 0


def cmd_unsuppress(a: argparse.Namespace) -> int:
    workflow.unsuppress(Case.open(a.cases, a.case_id), a.suppression_id, a.reason, examiner=a.examiner)
    print(f"Withdrew {a.suppression_id} and re-ran analysis.")
    return 0


def cmd_validate(a: argparse.Namespace) -> int:
    """Score the rules against public attack datasets listed in a manifest."""
    from . import validate
    manifest_path = validate.resolve_manifest(a.manifest or validate.DEFAULT_MANIFEST)
    data_dir = Path(a.data) if a.data else validate.DEFAULT_DATA
    manifest = validate.load_manifest(manifest_path)
    if a.fetch:
        for line in validate.fetch(manifest, data_dir, pin=a.pin):
            print(f"  {line}")
        if a.pin:
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            print(f"  pinned SHA-256 hashes in {manifest_path}")
    score = validate.run(manifest, data_dir, detections.load_rules(Path(a.rules) if a.rules else None))
    print(validate.render_markdown(score))
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(score, indent=2), encoding="utf-8")
    s = score["summary"]
    return 0 if s["detected"] == s["expected_detections"] and not s["unexplained_rule_hits"] else 1


def cmd_serve(a: argparse.Namespace) -> int:
    from .server import serve
    serve(Path(a.cases), host=a.host, port=a.port)
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    """Build each bundled sample breach as a full case and analyse it."""
    examiner = a.examiner or "demo-examiner"
    for case_id, (folder, title) in SAMPLE_CASES.items():
        print(f"\n== {case_id}: {title}")
        try:
            case = Case.create(a.cases, case_id, title=title, examiner=examiner)
        except FileExistsError:
            print(f"Case {case_id} already exists - re-running analysis.")
            case = Case.open(a.cases, case_id)
        else:
            for f in sorted((SAMPLES / folder).iterdir()):
                entry = case.ingest(f, examiner=examiner, note="bundled sample")
                print(f"  + {entry['evidence']:<32} sha256={entry['sha256'][:24]}...")
        result = workflow.analyze_case(case, examiner=examiner, year=2026)
        _print_summary(result)
        print(f"  Report:    {case.dir / 'report.html'}")
    print(f"\n  Dashboard: tracevault --cases {a.cases} serve")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tracevault", description="Evidence-first DFIR triage.")
    p.add_argument("--version", action="version", version=f"TraceVault {__version__}")
    p.add_argument("--cases", default="cases", help="case workspace root (default: ./cases)")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        return sp

    sp = add("case-new", cmd_case_new, "open a new case")
    sp.add_argument("case_id"); sp.add_argument("--title", default=""); sp.add_argument("--examiner")

    sp = add("ingest", cmd_ingest, "acquire evidence files into a case (hashed + logged)")
    sp.add_argument("case_id"); sp.add_argument("files", nargs="+")
    sp.add_argument("--examiner"); sp.add_argument("--note", default="")

    sp = add("analyze", cmd_analyze, "parse evidence, run detections, export report")
    sp.add_argument("case_id"); sp.add_argument("--examiner"); sp.add_argument("--year", type=int)
    sp.add_argument("--rules", help="custom rules JSON")

    sp = add("verify", cmd_verify, "verify ledger chain and evidence hashes")
    sp.add_argument("case_id")

    sp = add("anchor", cmd_anchor, "print the ledger head hash for external timestamping")
    sp.add_argument("case_id")

    sp = add("scan", cmd_scan, "triage loose log files without a case")
    sp.add_argument("files", nargs="+"); sp.add_argument("--year", type=int)
    sp.add_argument("--rules"); sp.add_argument("--json", action="store_true")
    sp.add_argument("--identities", help="identity map JSON {identity: [aliases]}")

    sp = add("suppress", cmd_suppress, "suppress reviewed findings (recorded in the custody ledger)")
    sp.add_argument("case_id"); sp.add_argument("--rule", required=True, help="rule id, e.g. TV-030")
    sp.add_argument("--reason", required=True)
    sp.add_argument("--verdict", choices=["false_positive", "expected_activity"], default="false_positive")
    sp.add_argument("--finding", metavar="EVENT_ID", help="suppress only the finding containing this event")
    sp.add_argument("--where", action="append", metavar="FIELD=VALUE", help="exact match (repeatable)")
    sp.add_argument("--where-regex", action="append", metavar="FIELD=REGEX", help="regex match (repeatable)")
    sp.add_argument("--examiner")

    sp = add("suppressions", cmd_suppressions, "list a case's suppressions")
    sp.add_argument("case_id")

    sp = add("unsuppress", cmd_unsuppress, "withdraw a suppression")
    sp.add_argument("case_id"); sp.add_argument("suppression_id"); sp.add_argument("--reason", required=True)
    sp.add_argument("--examiner")

    sp = add("validate", cmd_validate, "score detection rules against public attack datasets")
    sp.add_argument("--manifest", help="otrf (default), otrf-holdout, or a path to your own manifest")
    sp.add_argument("--data", help="dataset folder (default: $TRACEVAULT_DATA or ~/.tracevault/datasets)")
    sp.add_argument("--rules")
    sp.add_argument("--fetch", action="store_true", help="download datasets missing from --data")
    sp.add_argument("--pin", action="store_true",
                    help="maintainers: record downloaded SHA-256 hashes in the manifest file")
    sp.add_argument("--json-out", help="write the full scorecard as JSON")

    sp = add("serve", cmd_serve, "start the local dashboard")
    sp.add_argument("--host", default="127.0.0.1"); sp.add_argument("--port", type=int, default=8765)

    sp = add("demo", cmd_demo, "create and analyse the bundled sample breaches")
    sp.add_argument("--examiner")

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
