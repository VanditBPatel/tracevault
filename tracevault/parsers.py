"""Artifact parsers that turn raw evidence files into normalized Events.

Supported formats (auto-detected from content):
  * syslog / auth.log  - classic "Oct 21 02:10:01 host prog[pid]: msg" and RFC 5424-ish ISO stamps
  * winevt             - Windows event log exported as JSON Lines or a JSON array
  * web                - Apache / Nginx combined access log
  * cloudtrail         - AWS CloudTrail ({"Records": [...]}, JSON array or JSON Lines)
  * m365               - Microsoft 365 unified audit log (Purview CSV export or AuditData JSON)
  * okta               - Okta System Log (API JSON array or JSON Lines)
"""

from __future__ import annotations

import csv
import gzip
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import IO, Any, Callable, Iterable
from urllib.parse import unquote_plus

from .models import Event

# --------------------------------------------------------------------------- syslog

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<prog>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)
SYSLOG_ISO_RE = re.compile(
    # journalctl -o short-iso writes the offset as +0000 on older systemd, +00:00 on newer.
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s"
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
            ts = _iso(m["iso"])
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
    4697: "service.install",
    4698: "task.create",
    4720: "account.create",
    4732: "group.add",
    7045: "service.install",
    1102: "log.cleared",
}

SYSMON_KINDS = {
    1: "process.create",
    3: "network.connect",
    7: "image.load",
    8: "thread.remote",
    10: "process.access",
    11: "file.create",
    12: "registry.event",
    13: "registry.event",
    14: "registry.event",
    22: "dns.query",
}

# Windows / Sysmon field name -> normalized field name. Process fields from Security 4688 and
# Sysmon 1 land on the same names so one rule covers both sources.
WIN_FIELDS = (
    ("SubjectUserName", "actor"), ("LogonType", "logon_type"),
    ("NewProcessName", "process"), ("Image", "process"),
    ("ParentProcessName", "parent_process"), ("ParentImage", "parent_process"),
    ("CommandLine", "command_line"), ("ParentCommandLine", "parent_command_line"),
    ("ServiceName", "service_name"), ("ImagePath", "image_path"), ("ServiceFileName", "image_path"),
    ("TaskName", "task_name"),
    ("SourceImage", "source_image"), ("TargetImage", "target_image"),
    ("GrantedAccess", "granted_access"), ("CallTrace", "call_trace"),
    ("TargetFilename", "target_filename"), ("TargetObject", "target_object"),
    ("Details", "details"), ("EventType", "registry_op"),
    ("DestinationIp", "dest_ip"), ("DestinationPort", "dest_port"),
    ("DestinationHostname", "dest_host"), ("QueryName", "query_name"),
    ("ImageLoaded", "image_loaded"),
)

_MS_DATE_RE = re.compile(r"/Date\((-?\d+)\)/")  # ConvertTo-Json renders DateTime as /Date(ms)/


def _val(rec: dict, key: str) -> Any:
    v = rec.get(key)
    return None if v in (None, "", "-") else v


def _is_sysmon(rec: dict) -> bool:
    return "sysmon" in str(rec.get("Channel") or rec.get("SourceName") or "").lower()


def _local_time(rec: dict) -> str | None:
    """The event's own (possibly local-time) stamp: TimeCreated (Get-WinEvent, Winlogbeat)
    or EventTime (NXLog)."""
    value = rec.get("TimeCreated") or rec.get("EventTime")
    return str(value) if value else None


def _win_time(rec: dict, offset: float | None) -> datetime:
    """Best available UTC time: Sysmon's UtcTime; else the event's own stamp, corrected by the
    file's measured clock offset when it is a bare local time; else the collector's
    @timestamp (when the event was *received*, so slightly late)."""
    if rec.get("UtcTime"):
        return _iso(str(rec["UtcTime"]))
    local = _local_time(rec)
    if local:
        ms = _MS_DATE_RE.search(local)
        if ms:
            return datetime.fromtimestamp(int(ms[1]) / 1000, tz=timezone.utc)
        if local.endswith("Z") or re.search(r"[+-]\d{2}:?\d{2}$", local):
            return _iso(local)
        if offset is not None:
            return _iso(local) + timedelta(seconds=offset)
    if rec.get("@timestamp"):
        return _iso(str(rec["@timestamp"]))
    return _iso(local) if local else datetime.fromtimestamp(0, tz=timezone.utc)


def _clock_offset(records: list[dict]) -> float | None:
    """Seconds to add to bare local stamps, learned from Sysmon events that carry both a local
    stamp and UtcTime (median, rounded to the nearest 15 minutes, as time zones are)."""
    diffs = []
    for rec in records:
        local = _local_time(rec)
        if rec.get("UtcTime") and local and not _MS_DATE_RE.search(local):
            try:
                diffs.append((_iso(str(rec["UtcTime"])) - _iso(local)).total_seconds())
            except ValueError:
                continue
    if not diffs:
        return None
    diffs.sort()
    return round(diffs[len(diffs) // 2] / 900) * 900


def parse_winevt(path: Path) -> list[Event]:
    """Parse Windows Security/System and Sysmon events exported as JSON (Get-WinEvent |
    ConvertTo-Json, Winlogbeat-style flattened JSON as in the OTRF Security-Datasets)."""
    records = _json_records(path) or []
    offset = _clock_offset(records)
    events: list[Event] = []
    for rec in records:
        event_id = int(rec.get("EventID", rec.get("Id", 0)))
        sysmon = _is_sysmon(rec)
        kind = (SYSMON_KINDS.get(event_id, f"sysmon.{event_id}") if sysmon
                else WIN_EVENT_KINDS.get(event_id, f"win.{event_id}"))
        ts = _win_time(rec, offset)

        fields: dict = {"event_id": event_id, "channel": rec.get("Channel")}
        for src, dst in WIN_FIELDS:
            if _val(rec, src) is not None and dst not in fields:
                fields[dst] = rec[src]

        if sysmon:
            user = _val(rec, "User")
        elif event_id == 4732:  # TargetUserName is the group, MemberName is who was added
            fields["group"] = rec.get("TargetUserName")
            user = _val(rec, "MemberName") or _val(rec, "MemberSid")
        elif event_id == 4688:
            user = _val(rec, "SubjectUserName") or _val(rec, "TargetUserName")
        else:
            user = _val(rec, "TargetUserName")

        src_ip = _val(rec, "IpAddress")
        if src_ip in ("::1", "127.0.0.1"):
            src_ip = None

        host = rec.get("Computer") or rec.get("Hostname")
        if not host and isinstance(rec.get("host"), dict):
            host = rec["host"].get("name")
        events.append(Event(ts=ts, source=path.name, kind=kind, host=host or "unknown",
                            message=_win_message(event_id, kind, user, fields, rec),
                            raw=json.dumps(rec), user=user, src_ip=src_ip, fields=fields))
    return events


def _basename(p: Any) -> str:
    return str(p or "?").replace("/", "\\").rsplit("\\", 1)[-1]


def _win_message(event_id: int, kind: str, user: str | None, fields: dict, rec: dict) -> str:
    if kind == "process.create":
        return f"Process created: {fields.get('command_line') or fields.get('process')}"
    if kind == "process.access":
        return (f"{_basename(fields.get('source_image'))} opened {_basename(fields.get('target_image'))} "
                f"(access {fields.get('granted_access')})")
    if kind == "file.create":
        return f"{_basename(fields.get('process'))} wrote {fields.get('target_filename')}"
    if kind == "registry.event":
        details = f" = {fields['details']}" if fields.get("details") else ""
        return f"{fields.get('registry_op') or 'Registry'} {fields.get('target_object')}{details}"
    if kind == "network.connect":
        return f"{_basename(fields.get('process'))} -> {fields.get('dest_ip')}:{fields.get('dest_port')}"
    if kind == "thread.remote":
        return f"{_basename(fields.get('source_image'))} created a thread in {_basename(fields.get('target_image'))}"
    if kind == "image.load":
        return f"{_basename(fields.get('process'))} loaded {fields.get('image_loaded')}"
    if kind == "dns.query":
        return f"{_basename(fields.get('process'))} resolved {fields.get('query_name')}"
    if kind == "service.install":
        return f"Service installed: {fields.get('service_name')} -> {fields.get('image_path')}"
    if event_id == 4732:
        return f"{user} added to group {fields.get('group')}"
    if rec.get("Message"):
        return str(rec["Message"]).splitlines()[0][:300]
    label = WIN_EVENT_KINDS.get(event_id, kind)
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


# --------------------------------------------------------------------------- AWS CloudTrail

def parse_cloudtrail(path: Path) -> list[Event]:
    """Parse AWS CloudTrail records. Host is "aws:<account id>"."""
    events: list[Event] = []
    for rec in _json_records(path) or []:
        ident = rec.get("userIdentity") or {}
        user_type = ident.get("type")
        issuer = (ident.get("sessionContext") or {}).get("sessionIssuer") or {}
        user = (ident.get("userName") or issuer.get("userName")
                or (ident.get("arn") or "").rsplit("/", 1)[-1] or None)
        if user_type == "Root":
            user = "root"

        name = rec.get("eventName", "")
        error = rec.get("errorCode") or ""
        request = rec.get("requestParameters") or {}
        fields: dict[str, Any] = {
            "event_name": name,
            "event_source": rec.get("eventSource"),
            "region": rec.get("awsRegion"),
            "user_type": user_type,
            "user_agent": rec.get("userAgent", ""),
            "error_code": error,
            "request": json.dumps(request, sort_keys=True),
        }
        if ident.get("accessKeyId"):
            fields["access_key"] = ident["accessKeyId"]
        if isinstance(request, dict) and request.get("userName"):
            fields["target_user"] = request["userName"]  # IAM user being created/changed

        if name == "ConsoleLogin":
            ok = (rec.get("responseElements") or {}).get("ConsoleLogin") == "Success"
            kind = "auth.success" if ok else "auth.failure"
            fields["mfa_used"] = (rec.get("additionalEventData") or {}).get("MFAUsed")
        elif "AccessDenied" in error or "UnauthorizedOperation" in error:
            kind = "cloud.denied"
        else:
            kind = "cloud.api"

        src_ip = _clean_ip(rec.get("sourceIPAddress"))
        if src_ip is None and rec.get("sourceIPAddress"):
            fields["source_service"] = rec["sourceIPAddress"]  # e.g. "ec2.amazonaws.com"

        summary = ", ".join(f"{k}={_short(v)}" for k, v in list(request.items())[:3])
        message = f"{name}{f' ({summary})' if summary else ''} by {user or '?'}"
        if kind.startswith("auth."):
            message = f"Console login {'succeeded' if kind == 'auth.success' else 'failed'} for {user} (MFA: {fields['mfa_used'] or '?'})"
        if error:
            message += f" -> {error}"

        account = rec.get("recipientAccountId") or ident.get("accountId") or "unknown"
        events.append(Event(ts=_iso(rec["eventTime"]), source=path.name, kind=kind, host=f"aws:{account}",
                            message=message, raw=json.dumps(rec), user=user, src_ip=src_ip, fields=fields))
    return events


# --------------------------------------------------------------------------- Microsoft 365

M365_KINDS = {"UserLoggedIn": "auth.success", "UserLoginFailed": "auth.failure"}


def parse_m365(path: Path) -> list[Event]:
    """Parse the Microsoft 365 unified audit log (Purview CSV export, or the AuditData JSON)."""
    events: list[Event] = []
    for rec in _m365_records(path):
        op = rec.get("Operation", "")
        params = {p["Name"]: str(p.get("Value", "")) for p in rec.get("Parameters") or []
                  if isinstance(p, dict) and "Name" in p}
        param_str = "; ".join(f"{k}={v}" for k, v in params.items())
        fields = {
            "operation": op,
            "workload": rec.get("Workload"),
            "result": rec.get("ResultStatus"),
            "object": rec.get("ObjectId"),
            "parameters": param_str,
            "user_agent": _m365_extended(rec, "UserAgent") or "",
        }
        target = rec.get("ObjectId") or ""
        message = f"{op}{f' {target}' if target else ''}{f' [{param_str}]' if param_str else ''}"
        events.append(Event(ts=_iso(rec["CreationTime"]), source=path.name,
                            kind=M365_KINDS.get(op, "saas.activity"), host="m365", message=message,
                            raw=json.dumps(rec), user=rec.get("UserId"),
                            src_ip=_clean_ip(rec.get("ClientIP") or rec.get("ClientIPAddress")),
                            fields=fields))
    return events


def _m365_records(path: Path) -> list[dict]:
    first = next(iter(_lines(path)), "")
    if first.lstrip()[:1] in "[{":
        records = _json_records(path) or []
    else:  # Purview export: CSV whose AuditData column holds the JSON record
        with _open_text(path, newline="") as fh:
            records = [row for row in csv.DictReader(fh)]
    out = []
    for rec in records:
        audit = rec.get("AuditData")
        if isinstance(audit, str):
            try:
                rec = json.loads(audit)
            except json.JSONDecodeError:
                continue
        elif isinstance(audit, dict):
            rec = audit
        if isinstance(rec, dict) and "CreationTime" in rec:
            out.append(rec)
    return out


def _m365_extended(rec: dict, name: str) -> str | None:
    for prop in rec.get("ExtendedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == name:
            return prop.get("Value")
    return None


# --------------------------------------------------------------------------- Okta

OKTA_KINDS = {
    "user.mfa.okta_verify.deny_push": "mfa.deny",
    "system.push.send_factor_verify_push": "mfa.push",
}


def parse_okta(path: Path) -> list[Event]:
    """Parse the Okta System Log (GET /api/v1/logs output)."""
    events: list[Event] = []
    for rec in _json_records(path) or []:
        event_type = rec.get("eventType", "")
        outcome = rec.get("outcome") or {}
        actor = rec.get("actor") or {}
        client = rec.get("client") or {}
        geo = client.get("geographicalContext") or {}
        result = outcome.get("result")

        if event_type == "user.session.start":
            kind = "auth.success" if result == "SUCCESS" else "auth.failure"
        else:
            kind = OKTA_KINDS.get(event_type, "saas.activity")

        targets = "; ".join(t.get("alternateId") or t.get("displayName") or ""
                            for t in rec.get("target") or [] if isinstance(t, dict))
        fields = {
            "event_type": event_type,
            "outcome": result,
            "reason": outcome.get("reason"),
            "country": geo.get("country"),
            "city": geo.get("city"),
            "user_agent": (client.get("userAgent") or {}).get("rawUserAgent", ""),
            "targets": targets,
        }
        place = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)
        message = f"{rec.get('displayMessage') or event_type}: {result or '-'}"
        if outcome.get("reason"):
            message += f" - {outcome['reason']}"
        if place:
            message += f" from {place}"
        events.append(Event(ts=_iso(rec["published"]), source=path.name, kind=kind, host="okta",
                            message=message, raw=json.dumps(rec), user=actor.get("alternateId"),
                            src_ip=_clean_ip(client.get("ipAddress")), fields=fields))
    return events


# --------------------------------------------------------------------------- dispatch

PARSERS: dict[str, Callable[..., list[Event]]] = {
    "syslog": parse_syslog,
    "winevt": parse_winevt,
    "web": parse_web,
    "cloudtrail": parse_cloudtrail,
    "m365": parse_m365,
    "okta": parse_okta,
}


def _classify_json(rec: dict) -> str | None:
    if "eventVersion" in rec or ("eventSource" in rec and "eventName" in rec):
        return "cloudtrail"
    if "eventType" in rec and "published" in rec:
        return "okta"
    if "AuditData" in rec or ("Operation" in rec and "CreationTime" in rec):
        return "m365"
    if any(k in rec for k in ("TimeCreated", "UtcTime", "EventTime")) and ("EventID" in rec or "Id" in rec):
        return "winevt"
    return None


def detect_format(path: Path) -> str | None:
    """Sniff the content to pick a parser. Works on gzip-compressed logs too."""
    # journalctl output can start with "-- Logs begin at ..." / "-- Boot ... --" marker lines.
    first = next((line for line in _lines(path) if not line.startswith("-- ")), None)
    if first is None:
        return None
    if first.lstrip()[:1] in "[{":
        records = _json_records(path)
        return _classify_json(records[0]) if records else None
    if "AuditData" in first and "," in first:
        return "m365"
    if WEB_RE.match(first):
        return "web"
    if SYSLOG_RE.match(first) or SYSLOG_ISO_RE.match(first):
        return "syslog"
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
    mark_duplicates(events)
    return events


def mark_duplicates(events: list[Event], window: float = 2.0) -> int:
    """Windows logs one process start twice when both Security 4688 and Sysmon 1 are on.
    Mark the Security copy as a duplicate of the (richer) Sysmon copy so detections count the
    process once. Both stay in the timeline; nothing is deleted from the evidence."""
    sysmon: dict[tuple, list[Event]] = {}
    for e in events:
        if e.kind == "process.create" and e.fields.get("event_id") == 1 and e.get("command_line"):
            key = (e.host.split(".")[0].lower(), str(e.get("command_line")).strip().lower())
            sysmon.setdefault(key, []).append(e)
    marked = 0
    for e in events:
        if e.kind == "process.create" and e.fields.get("event_id") == 4688 and e.get("command_line"):
            key = (e.host.split(".")[0].lower(), str(e.get("command_line")).strip().lower())
            twin = next((s for s in sysmon.get(key, [])
                         if abs((s.ts - e.ts).total_seconds()) <= window), None)
            if twin:
                e.fields["duplicate_of"] = twin.id
                marked += 1
    return marked


# --------------------------------------------------------------------------- helpers

GZIP_MAGIC = b"\x1f\x8b"


def _open_text(path: Path, newline: str | None = None) -> IO[str]:
    """Open a log as text, transparently decompressing gzip (rotated logs such as auth.log.2.gz).
    Evidence is ingested byte-for-byte as collected; decompression only happens when reading."""
    with open(path, "rb") as fh:
        magic = fh.read(2)
    if magic == GZIP_MAGIC:
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace", newline=newline)
    return open(path, encoding="utf-8-sig", errors="replace", newline=newline)


def _lines(path: Path) -> Iterable[str]:
    try:
        with _open_text(path) as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                if line.strip():
                    yield line
    except (OSError, EOFError):  # truncated or corrupt gzip: keep what was read
        return


def _json_records(path: Path) -> list[dict] | None:
    """Load a JSON document ({"Records": [...]}, an array, or one object) or JSON Lines."""
    try:
        with _open_text(path) as fh:
            text = fh.read().strip()
    except (OSError, EOFError):
        return None
    if not text or text[0] not in "[{":
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for line in text.splitlines():
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if isinstance(data, dict):
        data = data["Records"] if isinstance(data.get("Records"), list) else [data]
    return [r for r in data if isinstance(r, dict)] if isinstance(data, list) else None


def _clean_ip(value: Any) -> str | None:
    """Normalize "1.2.3.4", "1.2.3.4:5678" or "[::1]:443"; anything else (service names) -> None."""
    if not value:
        return None
    s = str(value).strip()
    if s.startswith("["):
        s = s[1:s.find("]")]
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def _short(value: Any, limit: int = 60) -> str:
    s = value if isinstance(value, str) else json.dumps(value)
    return s if len(s) <= limit else s[: limit - 3] + "..."


_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")
_FRACTION = re.compile(r"\.(\d+)")


def _iso(value: str) -> datetime:
    # Normalise what Python 3.10's fromisoformat rejects: "Z", a +HHMM offset (journalctl), and
    # fractions that are not exactly 3 or 6 digits (Windows writes seven, some tools write one).
    s = str(value).strip().replace("Z", "+00:00")
    if "T" in s or " " in s:
        s = _TZ_NO_COLON.sub(r"\1:\2", s)
    s = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)
    return _to_utc(datetime.fromisoformat(s))


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
