"""Measure detection accuracy against public attack datasets.

A manifest lists datasets, the rules each one *should* trigger (`expect`), extra hits that a
reviewer confirmed are genuine (`also_ok`, with the reason), and rules that fire because of how
the data was captured (`known_artifacts`). Everything else that fires is "unexplained" and
counts against precision until someone reviews it.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import detections, parsers

MANIFEST_DIR = Path(__file__).resolve().parent / "datasets"
# Bundled manifests, by name: the tuning set and the held-out set (see docs/VALIDATION.md).
MANIFESTS = {"otrf": MANIFEST_DIR / "otrf.json", "otrf-holdout": MANIFEST_DIR / "otrf-holdout.json"}
DEFAULT_MANIFEST = "otrf"
# Downloads live outside the package so an installed copy stays read-only and small.
DEFAULT_DATA = Path(os.environ.get("TRACEVAULT_DATA") or Path.home() / ".tracevault" / "datasets")
MAX_DOWNLOAD = 50 * 1024 * 1024


def resolve_manifest(name_or_path: str) -> Path:
    """A bundled manifest name (otrf, otrf-holdout) or a path to your own manifest."""
    if name_or_path in MANIFESTS:
        return MANIFESTS[name_or_path]
    path = Path(name_or_path)
    if not path.is_file():
        raise ValueError(f"Unknown manifest {name_or_path!r}: use one of {', '.join(MANIFESTS)} or a file path")
    return path


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fetch(manifest: dict[str, Any], data_dir: Path, pin: bool = False) -> list[str]:
    """Download each dataset archive and extract only its JSON files (by basename, so no
    archive path can escape the data directory). Verifies pinned SHA-256 hashes."""
    log = []
    data_dir.mkdir(parents=True, exist_ok=True)
    for ds in manifest["datasets"]:
        target = data_dir / ds["name"]
        if target.is_dir() and any(target.glob("*.json")):
            log.append(f"cached  {ds['name']}")
            continue
        url = manifest["base_url"] + ds["path"]
        if not url.startswith("https://"):
            raise ValueError(f"Refusing non-HTTPS download: {url}")
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - https only, checked above
                blob = resp.read(MAX_DOWNLOAD + 1)
        except (urllib.error.URLError, TimeoutError) as exc:
            log.append(f"FAILED  {ds['name']}: {exc} ({url})")
            continue
        if len(blob) > MAX_DOWNLOAD:
            raise IOError(f"{ds['name']} exceeds {MAX_DOWNLOAD} bytes")
        digest = hashlib.sha256(blob).hexdigest()
        if ds.get("sha256") and ds["sha256"] != digest:
            raise IOError(f"{ds['name']}: SHA-256 mismatch (expected {ds['sha256']}, got {digest})")
        if pin:
            ds["sha256"] = digest
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for member in zf.infolist():
                name = Path(member.filename).name
                if member.is_dir() or not name.lower().endswith(".json"):
                    continue
                (target / name).write_bytes(zf.read(member))
        log.append(f"fetched {ds['name']} ({len(blob):,} B, sha256 {digest[:16]}...)")
    return log


def run(manifest: dict[str, Any], data_dir: Path, rules: list[dict] | None = None) -> dict[str, Any]:
    rules = rules if rules is not None else detections.load_rules()
    artifacts = manifest.get("known_artifacts", {})
    rows = []
    for ds in manifest["datasets"]:
        files = sorted((data_dir / ds["name"]).glob("*.json"))
        if not files:
            rows.append({"name": ds["name"], "missing": True, "expect": ds["expect"]})
            continue
        events = parsers.parse_files(files)
        findings = detections.run(events, rules)
        fired = Counter(f.rule_id for f in findings)
        expect, also_ok = set(ds["expect"]), set(ds.get("also_ok", {}))
        rows.append({
            "name": ds["name"],
            "technique": ds.get("technique"),
            "events": len(events),
            "expect": sorted(expect),
            "hits": sorted(expect & set(fired)),
            "misses": sorted(expect - set(fired)),
            "artifacts": sorted(set(fired) & set(artifacts)),
            "also_ok": sorted(set(fired) & also_ok),
            "unexplained": {r: n for r, n in sorted(fired.items())
                            if r not in expect and r not in artifacts and r not in also_ok},
            "fired": dict(sorted(fired.items())),
        })

    present = [r for r in rows if not r.get("missing")]
    expected_total = sum(len(r["expect"]) for r in present)
    hit_total = sum(len(r["hits"]) for r in present)
    per_rule: dict[str, dict[str, int]] = {}
    for r in present:
        for rid in r["expect"]:
            stat = per_rule.setdefault(rid, {"hits": 0, "misses": 0, "unexplained": 0})
            stat["hits" if rid in r["hits"] else "misses"] += 1
        for rid in r["unexplained"]:
            per_rule.setdefault(rid, {"hits": 0, "misses": 0, "unexplained": 0})["unexplained"] += 1

    return {
        "source": manifest.get("source"),
        "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rules": len(rules),
        "datasets": rows,
        "summary": {
            "datasets": len(present),
            "missing": len(rows) - len(present),
            "events": sum(r["events"] for r in present),
            "expected_detections": expected_total,
            "detected": hit_total,
            "detection_rate": round(hit_total / expected_total, 3) if expected_total else None,
            "unexplained_rule_hits": sum(len(r["unexplained"]) for r in present),
            "datasets_with_unexplained": sum(bool(r["unexplained"]) for r in present),
        },
        "per_rule": dict(sorted(per_rule.items())),
        "known_artifacts": artifacts,
    }


def render_markdown(score: dict[str, Any]) -> str:
    s = score["summary"]
    rate = f"{s['detection_rate']:.0%}" if s["detection_rate"] is not None else "n/a"
    out = [
        f"| Datasets | Events | Expected detections | Detected | Detection rate | Unexplained rule hits |",
        "|---|---|---|---|---|---|",
        f"| {s['datasets']} | {s['events']:,} | {s['expected_detections']} | {s['detected']} | **{rate}** | "
        f"{s['unexplained_rule_hits']} (in {s['datasets_with_unexplained']} datasets) |",
        "",
        "| Dataset | ATT&CK | Events | Expected | Missed | Unexplained hits |",
        "|---|---|---|---|---|---|",
    ]
    for r in score["datasets"]:
        if r.get("missing"):
            out.append(f"| {r['name']} | | not downloaded | {', '.join(r['expect'])} | | |")
            continue
        unexplained = ", ".join(f"{k} x{v}" for k, v in r["unexplained"].items()) or "-"
        out.append(f"| {r['name']} | {r['technique']} | {r['events']:,} | {', '.join(r['expect'])} | "
                   f"{', '.join(r['misses']) or '-'} | {unexplained} |")
    return "\n".join(out)
