"""Link the many spellings of one person across systems into a single identity.

`priya` (AWS IAM), `priya@acme.io` (Okta, Microsoft 365) and `ACME\\priya` (Windows) are the
same human. Auto-linking lowercases the name and strips a DOMAIN\\ prefix and an @domain
suffix. When that is wrong (two different "sam"s) or not enough (`p.shah` is also Priya),
an analyst writes an identity map, which always wins:

  {"Priya Shah": ["priya", "priya@acme.io", "p.shah"], "Sam (vendor)": ["sam@vendor.example"]}

Each identity gets a status, derived only from attacker-attributed evidence:
  created      the account was created during the attack (backdoor)
  compromised  a login as this identity succeeded as part of the attack
  targeted     only failed logins / MFA prompts against it
  involved     it appears in findings in some other way
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding

STATUS_RANK = {"involved": 1, "targeted": 2, "compromised": 3, "created": 4}
TARGETED_KINDS = {"auth.failure", "mfa.push", "mfa.deny"}


def load_map(path: Path | None) -> dict[str, str]:
    """Read {identity: [aliases]} and return {alias (lowercase): identity}."""
    if not path or not Path(path).exists():
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    mapping: dict[str, str] = {}
    for identity, aliases in data.items():
        mapping[identity.lower()] = identity
        for alias in aliases:
            mapping[str(alias).strip().lower()] = identity
    return mapping


def canonical(name: str, mapping: dict[str, str] | None = None) -> str:
    mapping = mapping or {}
    key = name.strip().lower()
    if key in mapping:
        return mapping[key]
    if "\\" in key:
        key = key.split("\\", 1)[1]
    if "@" in key:
        key = key.split("@", 1)[0]
    return mapping.get(key, key)


def system_label(host: str) -> str:
    if host.startswith("aws:"):
        return f"AWS {host[4:]}"
    return {"m365": "Microsoft 365", "okta": "Okta"}.get(host, host)


def build(findings: list[Finding], mapping: dict[str, str] | None = None) -> list[dict[str, Any]]:
    mapping = mapping or {}
    ids: dict[str, dict[str, Any]] = {}

    def touch(name: str | None, host: str, ts: str, status: str = "involved") -> str | None:
        if not name:
            return None
        ident = canonical(name, mapping)
        rec = ids.setdefault(ident, {"identity": ident, "status": "involved", "aliases": set(),
                                     "systems": set(), "finding_ids": set(),
                                     "first_seen": ts, "last_seen": ts,
                                     "linked_by": "map" if name.strip().lower() in mapping else "auto"})
        rec["aliases"].add(name)
        rec["systems"].add(system_label(host))
        rec["first_seen"] = min(rec["first_seen"], ts)
        rec["last_seen"] = max(rec["last_seen"], ts)
        if name.strip().lower() in mapping:
            rec["linked_by"] = "map"
        if STATUS_RANK[status] > STATUS_RANK[rec["status"]]:
            rec["status"] = status
        return ident

    for idx, f in enumerate(findings):
        for e in f.attributed():
            ts = e.ts.isoformat()
            if e.kind == "account.create":
                status = "created"
            elif e.kind == "auth.success":
                status = "compromised"
            elif e.kind in TARGETED_KINDS:
                status = "targeted"
            else:
                status = "involved"
            for ident in (touch(e.user, e.host, ts, status),
                          touch(e.get("target_user") if e.get("event_name") else None, e.host, ts,
                                "created" if e.get("event_name") == "CreateUser" else "involved")):
                if ident:
                    ids[ident]["finding_ids"].add(idx)

    out = []
    for rec in ids.values():
        out.append({
            "identity": rec["identity"],
            "status": rec["status"],
            "aliases": sorted(rec["aliases"], key=str.lower),
            "systems": sorted(rec["systems"]),
            "findings": len(rec["finding_ids"]),
            "first_seen": rec["first_seen"],
            "last_seen": rec["last_seen"],
            "linked_by": rec["linked_by"] if len(rec["aliases"]) > 1 or rec["linked_by"] == "map" else None,
        })
    out.sort(key=lambda r: (-STATUS_RANK[r["status"]], -r["findings"], r["identity"]))
    return out
