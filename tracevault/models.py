"""Core data types shared by parsers, detections and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """One normalized artifact record (a log line, an event-log entry, ...)."""

    ts: datetime  # always timezone-aware UTC
    source: str  # evidence file the event came from
    kind: str  # normalized category, e.g. "auth.failure", "process.create"
    host: str
    message: str
    raw: str
    user: str | None = None
    src_ip: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def get(self, name: str) -> Any:
        """Look up a top-level attribute first, then the parser-specific fields."""
        if name in ("ts", "source", "kind", "host", "message", "raw", "user", "src_ip", "id"):
            return getattr(self, name)
        return self.fields.get(name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts.isoformat(),
            "source": self.source,
            "kind": self.kind,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "message": self.message,
            "fields": self.fields,
        }


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """A detection rule hit, with the evidence events that triggered it."""

    rule_id: str
    title: str
    severity: str
    tactic: str
    technique: str
    technique_name: str
    description: str
    summary: str
    ts: datetime
    events: list[Event]

    def entities(self) -> dict[str, list[str]]:
        hosts = sorted({e.host for e in self.events if e.host})
        users = sorted({e.user for e in self.events if e.user})
        ips = sorted({e.src_ip for e in self.events if e.src_ip})
        return {"hosts": hosts, "users": users, "ips": ips}

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "tactic": self.tactic,
            "technique": self.technique,
            "technique_name": self.technique_name,
            "description": self.description,
            "summary": self.summary,
            "ts": self.ts.isoformat(),
            "event_ids": [e.id for e in self.events],
            "entities": self.entities(),
        }
