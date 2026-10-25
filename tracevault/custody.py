"""Case workspace with a tamper-evident chain-of-custody ledger.

Layout of a case directory:

  cases/<CASE-ID>/
    case.json          case metadata
    evidence/          read-only working copies of every ingested artifact
    ledger.jsonl       append-only, hash-chained custody log
    analysis.json      latest analysis output
    report.html        latest exported report

Every ledger entry stores the SHA-256 of the previous entry, so altering, deleting or
re-ordering any record breaks the chain. Evidence files are re-hashed on verification,
so a modified artifact is caught as well. The ledger head hash can be published to an
external timestamping service (or a public blockchain) to prove the record existed at
a point in time - see `Case.anchor()`.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
CASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
# Names Windows treats as devices, not files, whatever the extension (CON, NUL.txt, ...).
WINDOWS_DEVICE_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_examiner() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can fail in odd environments
        return "unknown"


def valid_case_id(case_id: str) -> bool:
    """fullmatch, not match: with `$`, re.match also accepts a trailing newline."""
    return (isinstance(case_id, str) and CASE_ID_RE.fullmatch(case_id) is not None
            and case_id.split(".")[0].upper() not in WINDOWS_DEVICE_NAMES)


def case_path(root: Path, case_id: str) -> Path:
    """The case folder, guaranteed to sit directly inside the cases root."""
    if not valid_case_id(case_id):
        raise ValueError(f"Invalid case id {case_id!r} (letters, digits, '.', '_', '-' only)")
    base = os.path.realpath(str(root))
    full = os.path.realpath(os.path.join(base, case_id))
    if not full.startswith(os.path.join(base, "")) or os.path.dirname(full) != base:
        raise ValueError(f"Invalid case id {case_id!r}: resolves outside the cases folder")
    return Path(full)


class Case:
    def __init__(self, root: Path, case_id: str):
        self.dir = case_path(root, case_id)
        self.id = case_id
        self.evidence_dir = self.dir / "evidence"
        self.ledger_path = self.dir / "ledger.jsonl"
        self.meta_path = self.dir / "case.json"

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def create(cls, root: Path, case_id: str, title: str = "", examiner: str | None = None) -> "Case":
        case = cls(root, case_id)
        if case.meta_path.exists():
            raise FileExistsError(f"Case {case_id} already exists at {case.dir}")
        case.evidence_dir.mkdir(parents=True, exist_ok=True)
        examiner = examiner or default_examiner()
        meta = {"id": case_id, "title": title or case_id, "examiner": examiner, "created_at": _now()}
        case.meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        case.log("case.create", examiner, details={"title": meta["title"]})
        return case

    @classmethod
    def open(cls, root: Path, case_id: str) -> "Case":
        case = cls(root, case_id)
        if not case.meta_path.exists():
            raise FileNotFoundError(f"No case {case_id} under {root}")
        return case

    @staticmethod
    def list(root: Path) -> list["Case"]:
        root = Path(root)
        if not root.is_dir():
            return []
        return [Case(root, p.name) for p in sorted(root.iterdir())
                if (p / "case.json").exists() and valid_case_id(p.name)]

    @property
    def meta(self) -> dict[str, Any]:
        return json.loads(self.meta_path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------ ledger

    def entries(self) -> list[dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        with open(self.ledger_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def log(self, action: str, actor: str, evidence: str | None = None,
            sha256: str | None = None, details: dict | None = None) -> dict[str, Any]:
        prior = self.entries()
        entry = {
            "seq": len(prior) + 1,
            "ts": _now(),
            "actor": actor,
            "action": action,
            "evidence": evidence,
            "sha256": sha256,
            "details": details or {},
            "prev_hash": prior[-1]["entry_hash"] if prior else GENESIS,
        }
        entry["entry_hash"] = _entry_hash(entry)
        with open(self.ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    # ------------------------------------------------------------------ evidence

    def evidence_files(self) -> list[Path]:
        return sorted(p for p in self.evidence_dir.iterdir() if p.is_file()) if self.evidence_dir.exists() else []

    def ingest(self, source: Path, examiner: str | None = None, note: str = "") -> dict[str, Any]:
        """Hash the original, copy it into the case, hash the copy, and log both hashes."""
        source = Path(source)
        examiner = examiner or default_examiner()
        original_hash = sha256_file(source)

        dest = self.evidence_dir / source.name
        n = 1
        while dest.exists():
            dest = self.evidence_dir / f"{source.stem}.{n}{source.suffix}"
            n += 1
        shutil.copy2(source, dest)
        copy_hash = sha256_file(dest)
        if copy_hash != original_hash:
            dest.unlink()
            raise IOError(f"Hash mismatch while copying {source} - acquisition aborted")
        os.chmod(dest, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

        return self.log("evidence.ingest", examiner, evidence=dest.name, sha256=copy_hash, details={
            "original_path": str(source.resolve()),
            "size_bytes": dest.stat().st_size,
            "note": note,
        })

    # ------------------------------------------------------------------ verification

    def verify(self) -> dict[str, Any]:
        problems: list[str] = []
        entries = self.entries()
        prev = GENESIS
        expected_hashes: dict[str, str] = {}

        for i, entry in enumerate(entries, start=1):
            if entry.get("seq") != i:
                problems.append(f"Entry {i}: sequence number is {entry.get('seq')} (records missing or reordered)")
            if entry.get("prev_hash") != prev:
                problems.append(f"Entry {i}: prev_hash does not match entry {i - 1} (chain broken)")
            if _entry_hash(entry) != entry.get("entry_hash"):
                problems.append(f"Entry {i}: content was modified after it was written")
            if entry.get("action") == "evidence.ingest" and entry.get("evidence"):
                expected_hashes[entry["evidence"]] = entry["sha256"]
            prev = entry.get("entry_hash", "")

        evidence_status = []
        on_disk = {p.name: p for p in self.evidence_files()}
        for name, expected in expected_hashes.items():
            path = on_disk.pop(name, None)
            if path is None:
                problems.append(f"Evidence {name} is missing from the case")
                evidence_status.append({"file": name, "expected": expected, "actual": None, "ok": False})
                continue
            actual = sha256_file(path)
            ok = actual == expected
            if not ok:
                problems.append(f"Evidence {name} hash changed since acquisition")
            evidence_status.append({"file": name, "expected": expected, "actual": actual, "ok": ok})
        for name in on_disk:
            problems.append(f"Evidence {name} is present but was never logged in the ledger")

        return {
            "ok": not problems,
            "entries": len(entries),
            "head": prev if entries else None,
            "evidence": evidence_status,
            "problems": problems,
            "checked_at": _now(),
        }

    def anchor(self) -> dict[str, Any]:
        """Return the ledger head - a single hash that commits to the entire custody history."""
        entries = self.entries()
        return {
            "case": self.id,
            "entries": len(entries),
            "head": entries[-1]["entry_hash"] if entries else None,
            "at": _now(),
        }
