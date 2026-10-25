"""Explainable rule engine.

Rules live in JSON (see rules.json) so analysts can read, review and extend them without
touching code. Three rule types are supported:

  match         one event satisfies the conditions
  threshold     N matching events from the same entity, each within `window` seconds of the last
                (with "distinct": "<field>", N distinct values of that field instead - e.g. spraying)
  followed_by   a `first` burst (min_count events) and then a `then` event from the same entity
                within `window` seconds of the burst ending
  field_change  consecutive matching events from the same entity whose `field` differs, less than
                `window` seconds apart (e.g. logins from two countries)

Conditions (`where`) map a field name to either a case-insensitive regex string or a
comparison object such as {"gt": 10000000} / {"lt": 400} / {"eq": 4625}.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import Event, Finding

DEFAULT_RULES = Path(__file__).with_name("rules.json")


def load_rules(path: Path | None = None) -> list[dict[str, Any]]:
    with open(path or DEFAULT_RULES, encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


def _value_ok(actual: Any, cond: Any) -> bool:
    if actual is None:
        return False
    if isinstance(cond, dict):
        try:
            num = float(actual)
        except (TypeError, ValueError):
            return False
        ops = {"gt": num.__gt__, "gte": num.__ge__, "lt": num.__lt__, "lte": num.__le__, "eq": num.__eq__}
        return all(ops[op](float(v)) for op, v in cond.items())
    return bool(_regex(str(cond)).search(str(actual)))


def matches(event: Event, spec: dict[str, Any]) -> bool:
    kind = spec.get("kind")
    if kind is not None:
        kinds = kind if isinstance(kind, list) else [kind]
        if event.kind not in kinds:
            return False
    return all(_value_ok(event.get(name), cond) for name, cond in spec.get("where", {}).items())


def _bursts(events: list[Event], window: int) -> list[list[Event]]:
    """Split time-ordered events into clusters whose consecutive gaps are <= window seconds."""
    clusters: list[list[Event]] = []
    for e in events:
        if clusters and (e.ts - clusters[-1][-1].ts).total_seconds() <= window:
            clusters[-1].append(e)
        else:
            clusters.append([e])
    return clusters


def _grouped(events: list[Event], spec: dict, group_by: str) -> dict[Any, list[Event]]:
    groups: dict[Any, list[Event]] = defaultdict(list)
    for e in events:
        if matches(e, spec):
            key = e.get(group_by)
            if key is not None:
                groups[key].append(e)
    return groups


# Explicit list rather than ip_address.is_private, which also treats reserved and
# documentation ranges (e.g. 203.0.113.0/24) as private.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128",
)]


def is_internal_ip(value: Any) -> bool:
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


def _finding(rule: dict, evs: list[Event], summary: str, key: Any = None,
             at: Event | None = None, context: list[Event] | None = None) -> Finding:
    # The same behaviour means something different from inside the network: a brute-forced
    # login from an internal host is lateral movement, not initial access.
    tactic = rule["tactic"]
    if key is not None and rule.get("internal_tactic") and is_internal_ip(key):
        tactic = rule["internal_tactic"]
    return Finding(
        rule_id=rule["id"], title=rule["title"], severity=rule["severity"], tactic=tactic,
        technique=rule["technique"], technique_name=rule.get("technique_name", ""),
        description=rule.get("description", ""), summary=summary, ts=(at or evs[0]).ts, events=evs,
        category=rule.get("category", "attack"), context=context or [],
    )


def _span(evs: list[Event]) -> str:
    return f"{evs[0].ts:%Y-%m-%d %H:%M:%S} - {evs[-1].ts:%H:%M:%S} UTC"


def run_rule(rule: dict, events: list[Event]) -> list[Finding]:
    rtype = rule.get("type", "match")

    if rtype == "match":
        return [_finding(rule, [e], f"[{e.host}] {e.message}") for e in events if matches(e, rule["match"])]

    if rtype == "threshold":
        out = []
        for key, evs in _grouped(events, rule["match"], rule["group_by"]).items():
            for burst in _bursts(evs, rule["window"]):
                distinct = rule.get("distinct")
                size = len({e.get(distinct) for e in burst} - {None}) if distinct else len(burst)
                if size >= rule["count"]:
                    users = sorted({e.user for e in burst if e.user})
                    if len(users) > 3:
                        target = f" targeting {len(users)} accounts"
                    else:
                        target = f" targeting {', '.join(users)}" if users else ""
                    kind = rule["match"].get("kind", "events")
                    kind = "/".join(kind) if isinstance(kind, list) else kind
                    out.append(_finding(rule, burst,
                        f"{len(burst)} {kind} by {key}{target} "
                        f"on {', '.join(sorted({e.host for e in burst}))} ({_span(burst)})", key))
        return out

    if rtype == "field_change":
        fld, window = rule["field"], rule["window"]
        out = []
        for key, evs in _grouped(events, rule["match"], rule["group_by"]).items():
            evs = [e for e in evs if e.get(fld)]
            for prev, cur in zip(evs, evs[1:]):
                gap = (cur.ts - prev.ts).total_seconds()
                if prev.get(fld) != cur.get(fld) and gap <= window:
                    out.append(_finding(rule, [prev, cur],
                        f"{key}: {fld} {prev.get(fld)} ({prev.src_ip or '?'}) -> {cur.get(fld)} "
                        f"({cur.src_ip or '?'}) {round(gap / 60)} min apart", key, at=cur, context=[prev]))
        return out

    if rtype == "followed_by":
        group_by, window = rule["group_by"], rule["window"]
        firsts = _grouped(events, rule["first"]["match"], group_by)
        thens = _grouped(events, rule["then"]["match"], group_by)
        out = []
        for key, evs in firsts.items():
            for burst in _bursts(evs, window):
                if len(burst) < rule["first"].get("min_count", 1):
                    continue
                end = burst[-1].ts
                follow = next((t for t in thens.get(key, [])
                               if 0 <= (t.ts - end).total_seconds() <= window), None)
                if follow:
                    out.append(_finding(rule, burst + [follow],
                        f"{len(burst)} failures from {key}, then success as "
                        f"'{follow.user}' on {follow.host} at {follow.ts:%H:%M:%S} UTC", key))
        return out

    raise ValueError(f"Unknown rule type {rtype!r} in rule {rule.get('id')}")


def run(events: list[Event], rules: list[dict] | None = None) -> list[Finding]:
    rules = rules if rules is not None else load_rules()
    findings = [f for rule in rules for f in run_rule(rule, events)]
    findings.sort(key=lambda f: (f.ts, f.rule_id))
    return findings
