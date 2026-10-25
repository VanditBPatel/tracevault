"""Artifact parsers that turn raw evidence files into normalized Events.

Supported formats (auto-detected from content):
  * syslog / auth.log  - classic "Oct 21 02:10:01 host prog[pid]: msg" and RFC 5424-ish ISO stamps
  * winevt             - Windows event log exported as JSON Lines (one event object per line)
  * web                - Apache / Nginx combined access log
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import unquote_plus

from .models import Event

# --------------------------------------------------------------------------- syslog

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<prog>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)
SYSLOG_ISO_RE = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s"
    r"(?P<host>\S+)\s(?P<prog>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)

_IP = r"[0-9a-fA-F.:]+"

# (program regex, event kind, message regex)
SYSLOG_RULES: list[tuple[re.Pattern, str, re.Pattern]] = [
    (re.compile(r"^sshd$"), "auth.failure",
     re.compile(rf"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>{_IP})")),
    (re.compile(r"^sshd$"), "auth.success",
     re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src_ip>{_IP})")),
    (re.compile(r"^sudo$"), "priv.sudo",
     re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.*)$")),
    (re.compile(r"^(useradd|adduser)$"), "account.create",
     re.compile(r"new user: name=(?P<new_user>[^,\s]+)")),
    (re.compile(r"^crontab$"), "persistence.cron",
     re.compile(r"\((?P<user>[^)]+)\) (?P<action>REPLACE|EDIT|INSTALL) \((?P<target_user>[^)]+)\)")),
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_syslog(path: Path, year: int | None = None) -> list[Event]:
    """Parse a syslog/auth.log file. Classic syslog has no year, so one is supplied."""
    year = year or datetime.now(timezone.utc).year
    events: list[Event] = []
    for line in _lines(path):
        m = SYSLOG_ISO_RE.match(line)
        if m:
            ts = _to_utc(datetime.fromisoformat(m["iso"].replace("Z", "+00:00")))
        else:
            m = SYSLOG_RE.match(line)
            if not m:
                continue
            hh, mm, ss = (int(x) for x in m["time"].split(":"))
            ts = datetime(year, _MONTHS[m["mon"]], int(m["day"]), hh, mm, ss, tzinfo=timezone.utc)

        prog, msg = m["prog"], m["msg"]
        kind, fields, user, src_ip = "syslog", {"program": prog}, None, None
        for prog_re, rule_kind, msg_re in SYSLOG_RULES:
            if not prog_re.match(prog):
                continue
            hit = msg_re.search(msg)
            if hit:
                kind = rule_kind
                groups = {k: v for k, v in hit.groupdict().items() if v is not None}
                user = groups.pop("user", None)
                src_ip = groups.pop("src_ip", None)
                fields.update(groups)
                break
        if kind == "account.create":
            user = fields.get("new_user")
        events.append(Event(ts=ts, source=path.name, kind=kind, host=m["host"], message=msg,
                            raw=line, user=user, src_ip=src_ip, fields=fields))
    return events


# --------------------------------------------------------------------------- windows

WIN_EVENT_KINDS = {
    4624: "auth.success",
    4625: "auth.failure",
    4688: "process.create",
    4698: "task.create",
    4720: "account.create",
    4732: "group.add",
    7045: "service.install",
    1102: "log.cleared",
}


def parse_winevt(path: Path) -> list[Event]:
    """Parse Windows events exported as JSON Lines (e.g. Get-WinEvent | ConvertTo-Json -Compress)."""
    events: list[Event] = []
    for line in _lines(path):
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        event_id = int(rec.get("EventID", 0))
        kind = WIN_EVENT_KINDS.get(event_id, f"win.{event_id}")
        ts = _to_utc(datetime.fromisoformat(str(rec["TimeCreated"]).replace("Z", "+00:00")))

        user = rec.get("TargetUserName")
        fields: dict = {"event_id": event_id}
        for src, dst in (("SubjectUserName", "actor"), ("LogonType", "logon_type"),
                         ("NewProcessName", "process"), ("ParentProcessName", "parent_process"),
                         ("CommandLine", "command_line"), ("ServiceName", "service_name"),
                         ("ImagePath", "image_path"), ("TaskName", "task_name")):
            if rec.get(src) not in (None, "", "-"):
                fields[dst] = rec[src]
        if event_id == 4732:  # TargetUserName is the group, MemberName is who was added
            fields["group"] = rec.get("TargetUserName")
            user = rec.get("MemberName")
        if event_id == 4688 and not user:
            user = rec.get("SubjectUserName")

        src_ip = rec.get("IpAddress")
        if src_ip in ("-", "", "::1", "127.0.0.1"):
            src_ip = None

        events.append(Event(ts=ts, source=path.name, kind=kind, host=rec.get("Computer", "unknown"),
                            message=rec.get("Message") or _win_message(event_id, user, fields),
                            raw=line, user=user, src_ip=src_ip, fields=fields))
    return events


def _win_message(event_id: int, user: str | None, fields: dict) -> str:
    if event_id == 4688:
        return f"Process created: {fields.get('command_line') or fields.get('process')}"
    if event_id == 7045:
        return f"Service installed: {fields.get('service_name')} -> {fields.get('image_path')}"
    if event_id == 4732:
        return f"{user} added to group {fields.get('group')}"
    label = WIN_EVENT_KINDS.get(event_id, f"Event {event_id}")
    return f"{label} ({event_id}) user={user or '-'}"


# --------------------------------------------------------------------------- web

WEB_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_web(path: Path) -> list[Event]:
    """Parse an Apache/Nginx combined access log.

    Access logs carry no hostname, so a "host_" filename prefix (web-01_access.log) names the server.
    """
    host = path.stem.split("_", 1)[0] if "_" in path.stem else path.stem
    events: list[Event] = []
    for line in _lines(path):
        m = WEB_RE.match(line)
        if not m:
            continue
        ts = _to_utc(datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z"))
        path_decoded = unquote_plus(m["path"])
        fields = {
            "method": m["method"],
            "path": path_decoded,
            "status": int(m["status"]),
            "bytes": 0 if m["bytes"] == "-" else int(m["bytes"]),
            "user_agent": m["ua"] or "",
        }
        user = None if m["user"] == "-" else m["user"]
        message = f'{m["method"]} {path_decoded} -> {m["status"]} ({fields["bytes"]} B)'
        events.append(Event(ts=ts, source=path.name, kind="web.request", host=host, message=message,
                            raw=line, user=user, src_ip=m["src_ip"], fields=fields))
    return events


# --------------------------------------------------------------------------- dispatch

PARSERS: dict[str, Callable[..., list[Event]]] = {
    "syslog": parse_syslog,
    "winevt": parse_winevt,
    "web": parse_web,
}


def detect_format(path: Path) -> str | None:
    """Sniff the first meaningful line to pick a parser."""
    for line in _lines(path):
        if line.startswith("{"):
            return "winevt"
        if WEB_RE.match(line):
            return "web"
        if SYSLOG_RE.match(line) or SYSLOG_ISO_RE.match(line):
            return "syslog"
        return None
    return None


def parse_file(path: Path, year: int | None = None) -> list[Event]:
    fmt = detect_format(path)
    if fmt is None:
        return []
    if fmt == "syslog":
        return parse_syslog(path, year=year)
    return PARSERS[fmt](path)


def parse_files(paths: Iterable[Path], year: int | None = None) -> list[Event]:
    """Parse every file, merge into one super-timeline, and assign stable event ids."""
    events: list[Event] = []
    for p in paths:
        events.extend(parse_file(Path(p), year=year))
    events.sort(key=lambda e: (e.ts, e.source))
    for i, e in enumerate(events, start=1):
        e.id = f"E{i:05d}"
    return events


def _lines(path: Path) -> Iterable[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.strip():
                yield line


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
