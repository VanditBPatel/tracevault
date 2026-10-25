"""Local investigation dashboard (stdlib only - nothing to install on an IR jump box).

Binds to 127.0.0.1 by default: case data is sensitive and the server has no authentication.
The examiner name sent with dashboard actions is recorded as given; it is not verified.
"""

from __future__ import annotations

import json
import re
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import suppressions, workflow
from .custody import CASE_ID_RE, Case

WEB_DIR = Path(__file__).with_name("web")
MAX_BODY = 64 * 1024
MAX_PAGE = 1000
EXAMINER_RE = re.compile(r"^[\w .@'-]{1,80}$")


class CaseCache:
    """Parsed analysis.json and the last custody verification per case.

    analysis.json can be tens of MB, so it is parsed once and reused until the file changes.
    Verification re-hashes all evidence, so it runs on first open, whenever the ledger changes,
    or when the analyst asks; the dashboard always shows when it last ran."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._analysis: dict[str, tuple[tuple, Any]] = {}
        self._verify: dict[str, tuple[tuple, Any]] = {}
        self._writers: dict[str, threading.Lock] = {}

    def writer(self, case_id: str) -> threading.Lock:
        """One writer per case at a time, so ledger appends and re-analysis never interleave."""
        with self._lock:
            return self._writers.setdefault(case_id, threading.Lock())

    @staticmethod
    def _sig(path: Path) -> tuple:
        try:
            st = path.stat()
            return (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return (None, None)

    def analysis(self, case: Case) -> dict[str, Any] | None:
        sig = self._sig(case.dir / "analysis.json")
        with self._lock:
            hit = self._analysis.get(case.id)
            if hit and hit[0] == sig:
                return hit[1]
        data = workflow.load_analysis(case)
        with self._lock:
            self._analysis[case.id] = (sig, data)
        return data

    def verification(self, case: Case, force: bool = False) -> dict[str, Any]:
        sig = self._sig(case.ledger_path)
        with self._lock:
            hit = self._verify.get(case.id)
            if hit and hit[0] == sig and not force:
                return hit[1]
        result = case.verify()
        with self._lock:
            self._verify[case.id] = (sig, result)
        return result


def make_handler(cases_root: Path):
    cache = CaseCache()

    class Handler(BaseHTTPRequestHandler):
        server_version = "TraceVault"

        def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
            print(f"[http] {self.address_string()} {fmt % args}")

        # -------------------------------------------------------------- helpers

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: Any, status: int = 200) -> None:
            self._send(status, json.dumps(data).encode("utf-8"), "application/json")

        def _error(self, status: int, msg: str) -> None:
            self._json({"error": msg}, status)

        def _case(self, case_id: str) -> Case | None:
            if not CASE_ID_RE.match(case_id):
                self._error(HTTPStatus.BAD_REQUEST, "invalid case id")
                return None
            try:
                return Case.open(cases_root, case_id)
            except FileNotFoundError:
                self._error(HTTPStatus.NOT_FOUND, "case not found")
                return None

        def _body(self) -> dict[str, Any] | None:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request too large")
                return None
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._error(HTTPStatus.BAD_REQUEST, "invalid JSON")
                return None
            if not isinstance(data, dict):
                self._error(HTTPStatus.BAD_REQUEST, "expected a JSON object")
                return None
            return data

        def _examiner(self, body: dict[str, Any]) -> str | None:
            name = str(body.get("examiner") or "").strip()
            if not EXAMINER_RE.match(name):
                self._error(HTTPStatus.BAD_REQUEST, "enter your examiner name (letters, digits, . @ ' -)")
                return None
            return f"{name} (dashboard)"

        def _case_payload(self, case: Case) -> dict[str, Any]:
            a = cache.analysis(case)
            slim = None
            if a is not None:
                # Ship only the events behind findings; the full timeline is paged via /events.
                needed = {eid for f in a["findings"] for eid in f["event_ids"]}
                slim = {k: v for k, v in a.items() if k != "timeline"}
                slim["finding_events"] = [e for e in a["timeline"] if e["id"] in needed]
                slim["timeline_total"] = len(a["timeline"])
                slim["timeline_flagged"] = sum(1 for e in a["timeline"] if e["rules"])
            active, revoked = suppressions.replay(case.entries())
            return {
                "case": case.meta,
                "analysis": slim,
                "ledger": case.entries(),
                "verification": cache.verification(case),
                "suppressions": {"active": active, "revoked": revoked},
            }

        # -------------------------------------------------------------- routes

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            parts = [p for p in url.path.split("/") if p]

            if not parts:
                return self._send(200, (WEB_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")

            if parts == ["api", "cases"]:
                return self._json([{**case.meta, **(workflow.load_summary(case) or {})}
                                   for case in Case.list(cases_root)])

            if len(parts) >= 3 and parts[:2] == ["api", "cases"]:
                case = self._case(parts[2])
                if case is None:
                    return None
                if len(parts) == 3:
                    return self._json(self._case_payload(case))
                if parts[3:] == ["events"]:
                    return self._events(case, parse_qs(url.query))
                if parts[3:] == ["report"]:
                    path = case.dir / "report.html"
                    if not path.exists():
                        return self._error(HTTPStatus.NOT_FOUND, "no report yet - run analysis first")
                    return self._send(200, path.read_bytes(), "text/html; charset=utf-8")

            return self._error(HTTPStatus.NOT_FOUND, "not found")

        def _events(self, case: Case, qs: dict[str, list[str]]) -> None:
            a = cache.analysis(case)
            if a is None:
                return self._error(HTTPStatus.NOT_FOUND, "no analysis yet")
            try:
                offset = max(0, int(qs.get("offset", ["0"])[0]))
                limit = min(MAX_PAGE, max(1, int(qs.get("limit", ["200"])[0])))
            except ValueError:
                return self._error(HTTPStatus.BAD_REQUEST, "offset/limit must be integers")
            rows = a["timeline"]
            if qs.get("flagged", ["0"])[0] == "1":
                rows = [e for e in rows if e["rules"]]
            q = qs.get("q", [""])[0].strip().lower()[:200]
            if q:
                rows = [e for e in rows if q in f"{e['message']} {e['host']} {e['user']} {e['kind']} {e['src_ip']}".lower()]
            return self._json({"total": len(rows), "offset": offset, "events": rows[offset:offset + limit]})

        def do_POST(self) -> None:  # noqa: N802
            parts = [p for p in urlparse(self.path).path.split("/") if p]
            if len(parts) < 4 or parts[:2] != ["api", "cases"]:
                return self._error(HTTPStatus.NOT_FOUND, "not found")
            case = self._case(parts[2])
            if case is None:
                return None
            action = parts[3:]

            if action == ["verify"]:
                return self._json(cache.verification(case, force=True))

            body = self._body()
            if body is None:
                return None
            examiner = self._examiner(body)
            if examiner is None:
                return None
            try:
                with cache.writer(case.id):
                    if action == ["analyze"]:
                        result = workflow.analyze_case(case, examiner=examiner)
                        return self._json({"risk": result["risk"], "findings": result["stats"]["findings"]})
                    if action == ["suppressions"]:
                        entry = workflow.suppress(case, body, examiner=examiner)
                        return self._json({"suppression": entry["details"]["id"]})
                    if len(action) == 3 and action[0] == "suppressions" and action[2] == "revoke":
                        workflow.unsuppress(case, action[1], str(body.get("reason", "")), examiner=examiner)
                        return self._json({"revoked": action[1]})
            except ValueError as exc:
                return self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return self._error(HTTPStatus.NOT_FOUND, "not found")

    return Handler


def serve(cases_root: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    httpd = ThreadingHTTPServer((host, port), make_handler(Path(cases_root)))
    print(f"TraceVault dashboard on http://{host}:{port}  (cases: {Path(cases_root).resolve()})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
