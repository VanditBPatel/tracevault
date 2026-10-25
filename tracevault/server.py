"""Local investigation dashboard (stdlib only - nothing to install on an IR jump box).

Binds to 127.0.0.1 by default: case data is sensitive and the server has no authentication.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import workflow
from .custody import CASE_ID_RE, Case

WEB_DIR = Path(__file__).with_name("web")


def make_handler(cases_root: Path):
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

        # -------------------------------------------------------------- routes

        def do_GET(self) -> None:  # noqa: N802
            parts = [p for p in urlparse(self.path).path.split("/") if p]

            if not parts:
                return self._send(200, (WEB_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")

            if parts == ["api", "cases"]:
                rows = []
                for case in Case.list(cases_root):
                    a = workflow.load_analysis(case) or {}
                    rows.append({**case.meta,
                                 "risk": a.get("risk"),
                                 "findings": a.get("stats", {}).get("findings")})
                return self._json(rows)

            if len(parts) >= 3 and parts[:2] == ["api", "cases"]:
                case = self._case(parts[2])
                if case is None:
                    return None
                if len(parts) == 3:
                    return self._json({
                        "case": case.meta,
                        "analysis": workflow.load_analysis(case),
                        "ledger": case.entries(),
                        "verification": case.verify(),
                    })
                if parts[3:] == ["report"]:
                    path = case.dir / "report.html"
                    if not path.exists():
                        return self._error(HTTPStatus.NOT_FOUND, "no report yet - run analysis first")
                    return self._send(200, path.read_bytes(), "text/html; charset=utf-8")

            return self._error(HTTPStatus.NOT_FOUND, "not found")

        def do_POST(self) -> None:  # noqa: N802
            parts = [p for p in urlparse(self.path).path.split("/") if p]
            if len(parts) == 4 and parts[:2] == ["api", "cases"] and parts[3] == "analyze":
                case = self._case(parts[2])
                if case is None:
                    return None
                result = workflow.analyze_case(case, examiner="dashboard")
                return self._json({"risk": result["risk"], "findings": result["stats"]["findings"]})
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
