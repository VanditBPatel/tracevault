import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tracevault import analysis, detections, identities, parsers, workflow  # noqa: E402
from tracevault.custody import Case  # noqa: E402

SAMPLES = ROOT / "tracevault" / "samples" / "case-001"
CLOUD = ROOT / "tracevault" / "samples" / "case-002"


def sample_events():
    return parsers.parse_files(sorted(SAMPLES.iterdir()), year=2026)


def cloud_events():
    return parsers.parse_files(sorted(CLOUD.iterdir()))


class ParserTests(unittest.TestCase):
    def test_formats_are_detected(self):
        self.assertEqual(parsers.detect_format(SAMPLES / "web-01_auth.log"), "syslog")
        self.assertEqual(parsers.detect_format(SAMPLES / "web-01_access.log"), "web")
        self.assertEqual(parsers.detect_format(SAMPLES / "FIN-WS02_security.jsonl"), "winevt")

    def test_syslog_extracts_auth_fields(self):
        events = parsers.parse_syslog(SAMPLES / "web-01_auth.log", year=2026)
        success = [e for e in events if e.kind == "auth.success" and e.user == "deploy"]
        self.assertEqual(len(success), 1)
        self.assertEqual(success[0].src_ip, "203.0.113.45")
        self.assertEqual(success[0].ts.isoformat(), "2026-10-21T02:12:40+00:00")
        sudo = next(e for e in events if e.kind == "priv.sudo" and e.user == "deploy")
        self.assertEqual(sudo.fields["command"], "/bin/bash")

    def test_web_path_is_url_decoded_and_host_from_filename(self):
        events = parsers.parse_web(SAMPLES / "web-01_access.log")
        self.assertTrue(all(e.host == "web-01" for e in events))
        self.assertIn("/uploads/shell.php?cmd=cat /etc/passwd", [e.fields["path"] for e in events])

    def test_winevt_group_add_maps_member(self):
        events = parsers.parse_winevt(SAMPLES / "FIN-WS02_security.jsonl")
        add = next(e for e in events if e.kind == "group.add")
        self.assertEqual(add.user, "helpdesk$")
        self.assertEqual(add.fields["group"], "Administrators")

    def test_iso_syslog(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "auth.log"
            p.write_text("2026-03-01T10:00:00.123+02:00 db-1 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
            (e,) = parsers.parse_file(p)
            self.assertEqual(e.kind, "auth.failure")
            self.assertEqual(e.ts.hour, 8)  # normalized to UTC

    def test_events_sorted_with_ids(self):
        events = sample_events()
        self.assertEqual([e.ts for e in events], sorted(e.ts for e in events))
        self.assertEqual(events[0].id, "E00001")


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = detections.run(sample_events())
        cls.ids = [f.rule_id for f in cls.findings]

    def test_expected_rules_fire(self):
        for rid in ["TV-001", "TV-002", "TV-003", "TV-010", "TV-011", "TV-012",
                    "TV-020", "TV-021", "TV-022", "TV-023", "TV-024", "TV-100", "TV-101"]:
            self.assertIn(rid, self.ids, rid)

    def test_benign_activity_not_flagged(self):
        # alice's single failed login and her nginx restart via sudo must not trigger anything
        for f in self.findings:
            self.assertNotIn("alice", f.entities()["users"], f.title)

    def test_brute_force_then_success_is_attributed(self):
        hits = [f for f in self.findings if f.rule_id == "TV-101"]
        by_ip = {f.entities()["ips"][0]: f for f in hits}
        self.assertEqual(by_ip["203.0.113.45"].tactic, "Initial Access")
        self.assertEqual(by_ip["10.0.0.15"].tactic, "Lateral Movement")
        self.assertEqual(by_ip["203.0.113.45"].events[-1].user, "deploy")

    def test_scanner_collapsed_to_one_finding(self):
        self.assertEqual(self.ids.count("TV-001"), 1)

    def test_numeric_conditions(self):
        rule = {"id": "X", "title": "x", "severity": "low", "tactic": "Impact", "technique": "T0",
                "type": "match", "match": {"kind": "web.request", "where": {"bytes": {"gt": 40000000}}}}
        self.assertEqual(len(detections.run_rule(rule, sample_events())), 1)

    def test_unknown_rule_type_rejected(self):
        with self.assertRaises(ValueError):
            detections.run_rule({"id": "X", "type": "nope"}, [])


class CloudParserTests(unittest.TestCase):
    def test_formats_are_detected(self):
        self.assertEqual(parsers.detect_format(CLOUD / "aws_cloudtrail.json"), "cloudtrail")
        self.assertEqual(parsers.detect_format(CLOUD / "m365_audit.jsonl"), "m365")
        self.assertEqual(parsers.detect_format(CLOUD / "okta_system_log.json"), "okta")

    def test_cloudtrail_normalization(self):
        events = parsers.parse_cloudtrail(CLOUD / "aws_cloudtrail.json")
        root = events[0]
        self.assertEqual((root.kind, root.user, root.host), ("auth.success", "root", "aws:111122223333"))
        login = next(e for e in events if e.user == "priya" and e.kind == "auth.success")
        self.assertEqual(login.fields["mfa_used"], "No")
        denied = [e for e in events if e.kind == "cloud.denied"]
        self.assertEqual(len(denied), 6)  # AccessDenied, AccessDeniedException and UnauthorizedOperation

    def test_m365_ip_port_stripped_and_params_flattened(self):
        events = parsers.parse_m365(CLOUD / "m365_audit.jsonl")
        login = next(e for e in events if e.user == "priya@acme.example" and e.kind == "auth.success")
        self.assertEqual(login.src_ip, "203.0.113.80")
        rule = next(e for e in events if e.fields["operation"] == "New-InboxRule")
        self.assertIn("ForwardTo=invoices@acme-billing.example", rule.fields["parameters"])

    def test_m365_purview_csv_export(self):
        import csv
        record = json.loads((CLOUD / "m365_audit.jsonl").read_text().splitlines()[3])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit_export.csv"
            with open(p, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(["RecordId", "CreationDate", "RecordType", "Operation", "UserId", "AuditData"])
                w.writerow(["1", "2026-10-22T09:14:05", "ExchangeAdmin", "New-InboxRule", "priya@acme.example", json.dumps(record)])
            self.assertEqual(parsers.detect_format(p), "m365")
            (e,) = parsers.parse_file(p)
            self.assertEqual(e.fields["operation"], "New-InboxRule")

    def test_okta_mfa_kinds_and_geo(self):
        events = parsers.parse_okta(CLOUD / "okta_system_log.json")
        kinds = [e.kind for e in events]
        self.assertEqual(kinds.count("mfa.push"), 6)
        self.assertEqual(kinds.count("mfa.deny"), 4)
        last = [e for e in events if e.kind == "auth.success" and e.user == "priya@acme.example"][-1]
        self.assertEqual(last.fields["country"], "Netherlands")

    def test_clean_ip(self):
        self.assertEqual(parsers._clean_ip("1.2.3.4:5678"), "1.2.3.4")
        self.assertEqual(parsers._clean_ip("[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(parsers._clean_ip("2001:db8::1"), "2001:db8::1")
        self.assertIsNone(parsers._clean_ip("ec2.amazonaws.com"))


class CloudDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = detections.run(cloud_events())
        cls.ids = [f.rule_id for f in cls.findings]

    def test_expected_rules_fire(self):
        for rid in ["TV-100", "TV-101", "TV-102", "TV-200", "TV-201", "TV-202", "TV-203", "TV-204",
                    "TV-205", "TV-206", "TV-207", "TV-210", "TV-211", "TV-212", "TV-213", "TV-214"]:
            self.assertIn(rid, self.ids, rid)

    def test_benign_lookalikes_not_flagged(self):
        # marcus's newsletter inbox rule and deploy-bot's CloudFront-only bucket policy are fine
        self.assertEqual(self.ids.count("TV-210"), 1)
        self.assertEqual(self.ids.count("TV-207"), 1)
        for f in self.findings:
            self.assertNotIn("deploy-bot", f.entities()["users"], f.title)
            if f.rule_id != "TV-102" and f.rule_id != "TV-100" and f.rule_id != "TV-101":
                self.assertNotIn("marcus@acme.example", f.entities()["users"], f.title)

    def test_spray_counts_distinct_accounts(self):
        spray = next(f for f in self.findings if f.rule_id == "TV-102")
        self.assertEqual(len(spray.entities()["users"]), 6)
        self.assertIn("6 accounts", spray.summary)

    def test_impossible_travel(self):
        travel = next(f for f in self.findings if f.rule_id == "TV-214")
        self.assertEqual([e.fields["country"] for e in travel.events], ["United States", "Netherlands"])
        self.assertEqual(travel.ts, travel.events[-1].ts)  # dated at the suspicious login

    def test_mfa_fatigue_links_denials_to_login(self):
        f = next(f for f in self.findings if f.rule_id == "TV-213")
        self.assertEqual([e.kind for e in f.events], ["mfa.deny"] * 4 + ["auth.success"])

    def test_spray_not_triggered_by_one_user_failing(self):
        rule = next(r for r in detections.load_rules() if r["id"] == "TV-102")
        events = [e for e in sample_events() if e.src_ip == "10.0.0.15"]  # 6 failures, 1 account
        self.assertEqual(detections.run_rule(rule, events), [])


SYSMON_FIXTURE = [
    # Winlogbeat-style flattened records (OTRF format): Sysmon carries UtcTime, Security has
    # only a local TimeCreated 4 hours behind UTC.
    {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS1",
     "TimeCreated": "2020-10-18 19:50:05.910", "UtcTime": "2020-10-18 23:50:05.910",
     "Image": "C:\\Windows\\System32\\rundll32.exe", "User": "CORP\\alice",
     "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump 756 C:\\Temp\\lsass.dmp full",
     "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    {"EventID": 4688, "Channel": "Security", "Hostname": "WS1", "TimeCreated": "2020-10-18 19:50:05.911",
     "SubjectUserName": "alice", "TargetUserName": "-", "NewProcessName": "C:\\Windows\\System32\\rundll32.exe",
     "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump 756 C:\\Temp\\lsass.dmp full"},
    {"EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS1",
     "TimeCreated": "2020-10-18 19:50:06.000", "UtcTime": "2020-10-18 23:50:06.000",
     "SourceImage": "C:\\Windows\\System32\\rundll32.exe", "TargetImage": "C:\\windows\\system32\\lsass.exe",
     "GrantedAccess": "0x1fffff", "CallTrace": "C:\\windows\\SYSTEM32\\dbgcore.DLL+9447"},
    {"EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS1",
     "TimeCreated": "2020-10-18 19:50:07.000", "UtcTime": "2020-10-18 23:50:07.000",
     "SourceImage": "C:\\Windows\\System32\\wininit.exe", "TargetImage": "C:\\windows\\system32\\lsass.exe",
     "GrantedAccess": "0x1fffff"},
]


class SysmonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ws1.json"
        self.path.write_text("\n".join(json.dumps(r) for r in SYSMON_FIXTURE))
        self.events = parsers.parse_files([self.path])

    def tearDown(self):
        self.tmp.cleanup()

    def test_sysmon_kinds_and_fields(self):
        self.assertEqual(parsers.detect_format(self.path), "winevt")
        kinds = sorted(e.kind for e in self.events)
        self.assertEqual(kinds, ["process.access", "process.access", "process.create", "process.create"])
        access = next(e for e in self.events if e.kind == "process.access")
        self.assertEqual(access.get("granted_access"), "0x1fffff")
        self.assertIn("lsass.exe", access.message)

    def test_local_time_corrected_with_learned_offset(self):
        sec = next(e for e in self.events if e.get("event_id") == 4688)
        self.assertEqual(sec.ts.isoformat(), "2020-10-18T23:50:05.911000+00:00")

    def test_security_and_sysmon_duplicates_counted_once(self):
        sec = next(e for e in self.events if e.get("event_id") == 4688)
        sysmon = next(e for e in self.events if e.get("event_id") == 1)
        self.assertEqual(sec.fields["duplicate_of"], sysmon.id)
        hits = [f for f in detections.run(self.events) if f.rule_id == "TV-021"]
        self.assertEqual(len(hits), 1)

    def test_lsass_access_rule_respects_exclusions(self):
        hits = [f for f in detections.run(self.events) if f.rule_id == "TV-030"]
        self.assertEqual([f.events[0].get("source_image").rsplit("\\", 1)[-1] for f in hits], ["rundll32.exe"])

    def test_nxlog_eventtime_format(self):
        rec = {"EventID": 4720, "Channel": "Security", "Hostname": "WS2.corp.local", "host": "collector",
               "EventTime": "2020-09-14 08:05:44", "@timestamp": "2020-09-14T12:05:46.456Z",
               "TargetUserName": "backdoor"}
        p = Path(self.tmp.name) / "nx.json"
        p.write_text(json.dumps(rec))
        (e,) = parsers.parse_file(p)
        self.assertEqual((e.kind, e.host, e.user), ("account.create", "WS2.corp.local", "backdoor"))
        self.assertEqual(e.ts.isoformat(), "2020-09-14T12:05:46.456000+00:00")  # no offset known -> @timestamp


class RuleEngineTests(unittest.TestCase):
    def _event(self, **fields):
        from tracevault.models import Event
        from datetime import datetime, timezone
        return Event(ts=datetime(2026, 1, 1, tzinfo=timezone.utc), source="t", kind="task.create",
                     host="h", message="m", raw="", fields=fields)

    def test_not_blocks_require_every_condition(self):
        spec = {"kind": "task.create", "not": [{"task_name": "^\\\\Microsoft\\\\Windows\\\\", "actor": "\\$$"}]}
        builtin = self._event(task_name="\\Microsoft\\Windows\\Update", actor="WS1$")
        hidden = self._event(task_name="\\Microsoft\\Windows\\Update", actor="mallory")
        self.assertFalse(detections.matches(builtin, spec))
        self.assertTrue(detections.matches(hidden, spec))  # attacker hiding under the Microsoft path

    def test_any_blocks(self):
        spec = {"kind": "task.create", "any": [{"a": "x"}, {"b": "y"}]}
        self.assertTrue(detections.matches(self._event(b="y"), spec))
        self.assertFalse(detections.matches(self._event(c="z"), spec))


class ValidationHarnessTests(unittest.TestCase):
    def test_scorecard_classifies_hits(self):
        from tracevault import validate
        with tempfile.TemporaryDirectory() as d:
            data = Path(d)
            (data / "ds1").mkdir()
            (data / "ds1" / "x.json").write_text("\n".join(json.dumps(r) for r in SYSMON_FIXTURE))
            manifest = {"known_artifacts": {}, "datasets": [
                {"name": "ds1", "technique": "T1003.001", "expect": ["TV-030", "TV-032"],
                 "also_ok": {"TV-021": "reviewed"}},
                {"name": "absent", "expect": ["TV-001"]}]}
            score = validate.run(manifest, data)
            manifest["datasets"][0]["also_ok"] = {}
            unreviewed = validate.run(manifest, data)
        row = score["datasets"][0]
        self.assertEqual(row["hits"], ["TV-030"])
        self.assertEqual(row["misses"], ["TV-032"])
        self.assertEqual(row["also_ok"], ["TV-021"])
        self.assertEqual(row["unexplained"], {})
        self.assertEqual(score["summary"]["missing"], 1)
        self.assertEqual(score["summary"]["detection_rate"], 0.5)
        self.assertEqual(unreviewed["datasets"][0]["unexplained"], {"TV-021": 1})

    def test_fetch_extracts_only_json_by_basename(self):
        import io as _io
        import zipfile as _zip
        from unittest import mock
        from tracevault import validate
        buf = _io.BytesIO()
        with _zip.ZipFile(buf, "w") as zf:
            zf.writestr("../../evil.json", "{}")
            zf.writestr("readme.txt", "x")
        blob = buf.getvalue()

        class Resp(_io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        manifest = {"base_url": "https://example.invalid/", "datasets": [{"name": "z", "path": "z.zip"}]}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch("urllib.request.urlopen", return_value=Resp(blob)):
            validate.fetch(manifest, Path(d) / "data", pin=True)
            written = sorted(p.relative_to(d).as_posix() for p in Path(d).rglob("*") if p.is_file())
        self.assertEqual(written, ["data/z/evil.json"])
        self.assertEqual(len(manifest["datasets"][0]["sha256"]), 64)


class SuppressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.case = Case.create(self.root, "S-1", title="sup", examiner="tester")
        for f in sorted(SAMPLES.iterdir()):
            self.case.ingest(f, examiner="tester")
        self.base = workflow.analyze_case(self.case, examiner="tester", year=2026)

    def tearDown(self):
        for p in self.case.evidence_files():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        self.tmp.cleanup()

    def _scanner(self, result):
        return next(f for f in result["findings"] if f["rule_id"] == "TV-001")

    def test_rejects_bad_requests(self):
        from tracevault import suppressions as sup
        good = {"rule_id": "TV-001", "reason": "authorized scan", "scope": "where",
                "conditions": [{"field": "src_ip", "op": "equals", "value": "198.51.100.23"}]}
        sup.validate_request(good)
        for bad in ({**good, "reason": "no"}, {**good, "rule_id": "X"}, {**good, "scope": "all"},
                    {**good, "verdict": "meh"}, {**good, "conditions": []},
                    {**good, "conditions": [{"field": "src_ip", "op": "regex", "value": "("}]},
                    {**good, "conditions": [{"field": "Bad Field!", "op": "equals", "value": "x"}]},
                    {"rule_id": "TV-001", "reason": "valid reason", "scope": "finding", "fingerprints": ["zz"]}):
            with self.assertRaises(Exception):  # ValueError, or re.error for a broken regex
                sup.validate_request(bad)
        self.assertEqual([e["action"] for e in self.case.entries()][-1], "report.export")  # nothing logged

    def test_where_suppression_removes_finding_from_the_story(self):
        entry = workflow.suppress(self.case, {
            "rule_id": "TV-001", "verdict": "expected_activity", "reason": "authorized pentest scan",
            "scope": "where", "conditions": [{"field": "src_ip", "op": "equals", "value": "198.51.100.23"}]},
            examiner="analyst")
        result = workflow.load_analysis(self.case)
        self.assertEqual(entry["action"], "finding.suppress")
        self.assertEqual(result["stats"]["findings"], self.base["stats"]["findings"] - 1)
        self.assertEqual(result["stats"]["suppressed_findings"], 1)
        self.assertEqual(self._scanner(result)["suppressed"]["by"], "analyst")
        self.assertFalse(any(l.startswith("Reconnaissance") for l in result["narrative"]))
        self.assertNotIn("198.51.100.23", [x["value"] for x in result["iocs"]["ips"]])
        self.assertIn("authorized pentest scan", (self.case.dir / "report.html").read_text(encoding="utf-8"))
        self.assertTrue(self.case.verify()["ok"])

    def test_unsuppress_restores_and_is_logged(self):
        workflow.suppress(self.case, {"rule_id": "TV-001", "reason": "authorized pentest scan", "scope": "where",
                                      "conditions": [{"field": "src_ip", "op": "equals", "value": "198.51.100.23"}]},
                          examiner="analyst")
        with self.assertRaises(ValueError):
            workflow.unsuppress(self.case, "S9", "no such suppression", examiner="analyst")
        workflow.unsuppress(self.case, "S1", "scope did not include web-01", examiner="lead")
        result = workflow.load_analysis(self.case)
        self.assertEqual(result["stats"]["findings"], self.base["stats"]["findings"])
        self.assertIsNone(self._scanner(result)["suppressed"])
        from tracevault import suppressions as sup
        active, revoked = sup.replay(self.case.entries())
        self.assertEqual((active, revoked[0]["revoked_by"]), ([], "lead"))

    def test_finding_scope_survives_new_evidence(self):
        fps = self._scanner(self.base)["attributed_fps"]
        workflow.suppress(self.case, {"rule_id": "TV-001", "reason": "reviewed: lab scanner",
                                      "scope": "finding", "fingerprints": fps}, examiner="analyst")
        # New evidence that sorts first renumbers every event id.
        extra = self.root / "aaa_early_auth.log"
        extra.write_text("Oct 20 00:00:01 jump-01 sshd[1]: Accepted publickey for ops from 10.0.0.9 port 1 ssh2\n")
        self.case.ingest(extra, examiner="analyst")
        result = workflow.analyze_case(self.case, examiner="analyst", year=2026)
        self.assertNotEqual(self._scanner(result)["event_ids"], self._scanner(self.base)["event_ids"])
        self.assertIsNotNone(self._scanner(result)["suppressed"])

    def test_tampering_with_a_suppression_is_detected(self):
        workflow.suppress(self.case, {"rule_id": "TV-001", "reason": "authorized pentest scan", "scope": "where",
                                      "conditions": [{"field": "src_ip", "op": "equals", "value": "198.51.100.23"}]},
                          examiner="analyst")
        lines = self.case.ledger_path.read_text().splitlines()
        idx = next(i for i, l in enumerate(lines) if '"finding.suppress"' in l)
        entry = json.loads(lines[idx])
        entry["details"]["conditions"][0]["value"] = "203.0.113.45"  # quietly hide the real attacker
        lines[idx] = json.dumps(entry)
        self.case.ledger_path.write_text("\n".join(lines) + "\n")
        self.assertFalse(self.case.verify()["ok"])


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import threading
        from http.server import ThreadingHTTPServer
        from tracevault.server import make_handler
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        cls.case = Case.create(cls.root, "W-1", title="web", examiner="tester")
        for f in sorted(SAMPLES.iterdir()):
            cls.case.ingest(f, examiner="tester")
        workflow.analyze_case(cls.case, examiner="tester", year=2026)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.root))
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for p in cls.case.evidence_files():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        cls.tmp.cleanup()

    def _req(self, path, body=None):
        import urllib.error
        import urllib.request
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json"},
                                     method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_case_list_and_slim_payload(self):
        status, cases = self._req("/api/cases")
        self.assertEqual((status, cases[0]["id"], cases[0]["findings"]), (200, "W-1", 19))
        status, payload = self._req("/api/cases/W-1")
        a = payload["analysis"]
        self.assertNotIn("timeline", a)
        self.assertEqual(a["timeline_total"], 55)
        needed = {eid for f in a["findings"] for eid in f["event_ids"]}
        self.assertEqual({e["id"] for e in a["finding_events"]}, needed)

    def test_event_paging_and_search(self):
        _, page = self._req("/api/cases/W-1/events?offset=10&limit=5")
        self.assertEqual((page["total"], len(page["events"]), page["events"][0]["id"]), (55, 5, "E00011"))
        _, hits = self._req("/api/cases/W-1/events?q=shell.php")
        self.assertEqual(hits["total"], 3)
        status, _ = self._req("/api/cases/W-1/events?limit=x")
        self.assertEqual(status, 400)

    def test_suppress_requires_examiner_then_succeeds(self):
        body = {"rule_id": "TV-012", "reason": "approved backup job change", "scope": "where",
                "conditions": [{"field": "host", "op": "equals", "value": "web-01"}]}
        status, err = self._req("/api/cases/W-1/suppressions", body)
        self.assertEqual(status, 400)
        self.assertIn("examiner", err["error"])
        status, ok = self._req("/api/cases/W-1/suppressions", {**body, "examiner": "J. Doe"})
        self.assertEqual(status, 200)
        _, payload = self._req("/api/cases/W-1")
        self.assertEqual(payload["suppressions"]["active"][0]["by"], "J. Doe (dashboard)")
        status, _ = self._req(f"/api/cases/W-1/suppressions/{ok['suppression']}/revoke",
                              {"examiner": "J. Doe", "reason": "x"})
        self.assertEqual(status, 400)  # reason too short
        status, _ = self._req(f"/api/cases/W-1/suppressions/{ok['suppression']}/revoke",
                              {"examiner": "J. Doe", "reason": "change was not approved after all"})
        self.assertEqual(status, 200)

    def test_bad_case_id_and_body(self):
        self.assertEqual(self._req("/api/cases/..%2Fx")[0], 400)
        import urllib.error
        import urllib.request
        req = urllib.request.Request(self.base + "/api/cases/W-1/suppressions", data=b"not json", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)


class LinuxCollectionTests(unittest.TestCase):
    """Linux collector output: journal export, gzip-rotated logs, and the bash script itself."""

    def test_journal_export_parses(self):
        lines = ["-- Logs begin at Sat 2026-10-24 06:00:00 UTC. --",
                 "2026-10-25T05:00:01.123456+0000 web-02 sshd[812]: Failed password for invalid user admin from 203.0.113.99 port 4242 ssh2",
                 "-- Boot 0f3c --",
                 "2026-10-25T07:00:03.5+0530 web-02 sudo[900]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash"]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "web-02_journal.log"
            p.write_text("\n".join(lines) + "\n")
            self.assertEqual(parsers.detect_format(p), "syslog")
            events = parsers.parse_file(p)
        self.assertEqual([e.kind for e in events], ["auth.failure", "priv.sudo"])
        self.assertEqual(events[0].ts.isoformat(), "2026-10-25T05:00:01.123456+00:00")
        self.assertEqual(events[1].ts.isoformat(), "2026-10-25T01:30:03.500000+00:00")  # +0530 -> UTC

    def test_gzip_rotated_log_parses(self):
        import gzip
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "web-01_auth.log.2.gz"
            with gzip.open(p, "wt") as fh:
                fh.write((SAMPLES / "web-01_auth.log").read_text())
            gz_events = parsers.parse_files([p], year=2026)
        plain = parsers.parse_files([SAMPLES / "web-01_auth.log"], year=2026)
        self.assertEqual([(e.kind, e.ts, e.message) for e in gz_events], [(e.kind, e.ts, e.message) for e in plain])

    def test_script_version_and_line_endings(self):
        from tracevault import __version__
        from tracevault.cli import COLLECTORS
        raw = COLLECTORS["linux"].read_bytes()
        self.assertNotIn(b"\r\n", raw)  # CRLF breaks bash on Linux
        self.assertIn(f"COLLECTOR_VERSION='{__version__}'".encode(), raw)

    @unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "runs the bash collector; Linux/macOS only")
    def test_collector_end_to_end_on_fake_root(self):
        import gzip
        import subprocess
        from tracevault.cli import COLLECTORS
        with tempfile.TemporaryDirectory() as d:
            root, out = Path(d) / "root", Path(d) / "out"
            (root / "var/log/nginx").mkdir(parents=True)
            (root / "etc").mkdir()
            (root / "etc/hostname").write_text("web-01\n")
            auth = (SAMPLES / "web-01_auth.log").read_text().splitlines(keepends=True)
            (root / "var/log/auth.log").write_text("".join(auth[10:]))
            with gzip.open(root / "var/log/auth.log.2.gz", "wt") as fh:
                fh.write("".join(auth[:10]))
            (root / "var/log/nginx/access.log").write_text((SAMPLES / "web-01_access.log").read_text())
            secret = Path(d) / "shadow"
            secret.write_text("root:$6$secret\n")
            os.symlink(secret, root / "var/log/secure")  # must not be followed out of /var/log
            run = subprocess.run(["bash", str(COLLECTORS["linux"]), "--root", str(root), "--out", str(out),
                                  "--examiner", "tester", "--no-journal"], capture_output=True, text=True, timeout=120)
            self.assertEqual(run.returncode, 0, run.stderr)
            manifest = json.loads((out / "manifest.json").read_text())
            names = sorted(f["name"] for f in manifest["files"])
            self.assertEqual(names, ["web-01_auth.log", "web-01_auth.log.2.gz", "web-01_nginx_access.log"])
            self.assertFalse(any("secure" in p.name for p in out.iterdir()))
            case = Case.create(Path(d) / "cases", "LIN-1", examiner="tester")
            workflow.ingest_collection(case, out, examiner="tester")
            result = workflow.analyze_case(case, examiner="tester", year=2026)
            direct = detections.run(parsers.parse_files([SAMPLES / "web-01_auth.log", SAMPLES / "web-01_access.log"], year=2026))
            self.assertEqual(sorted(f["rule_id"] for f in result["findings"]), sorted(f.rule_id for f in direct))
            self.assertTrue(case.verify()["ok"])
            for p in case.evidence_files():
                os.chmod(p, stat.S_IWRITE | stat.S_IREAD)


class ServicePowerShellRuleTests(unittest.TestCase):
    """TV-040: the service manager running encoded PowerShell (PsExec / SMBExec / Empire style)."""

    SVC = "C:\\Windows\\System32\\services.exe"

    @classmethod
    def setUpClass(cls):
        cls.rule = next(r for r in detections.load_rules() if r["id"] == "TV-040")

    def _ev(self, kind, **fields):
        from datetime import datetime, timezone
        from tracevault.models import Event
        return Event(ts=datetime(2026, 1, 1, tzinfo=timezone.utc), source="t", kind=kind, host="h",
                     message="m", raw="", fields=fields)

    def test_matches_service_launching_encoded_powershell(self):
        for cmd in ("cmd.exe /C start /b powershell -noP -sta -w 1 -enc SQBm",
                    "powershell.exe -NoProfile -EncodedCommand SQBm",
                    "powershell -ec SQBm",
                    '"C:\\WINDOWS\\powershell.exe" -e SQBm'):
            self.assertTrue(detections.matches(self._ev("process.create", parent_process=self.SVC, command_line=cmd),
                                               self.rule["match"]), cmd)

    def test_matches_service_installed_with_encoded_powershell(self):
        image = "%COMSPEC% /C start /b C:\\Windows\\System32\\WindowsPowershell\\v1.0\\powershell -noP -enc SQBm"
        self.assertTrue(detections.matches(self._ev("service.install", image_path=image), self.rule["match"]))

    def test_ignores_lookalikes(self):
        negatives = [
            self._ev("process.create", parent_process=self.SVC, command_line="powershell.exe -ExecutionPolicy Bypass -File C:\\agent\\run.ps1"),
            self._ev("process.create", parent_process=self.SVC, command_line="powershell -exec bypass -c Get-Date"),
            self._ev("process.create", parent_process="C:\\Windows\\explorer.exe", command_line="powershell -enc SQBm"),
            self._ev("service.install", image_path="C:\\Program Files\\Agent\\agent.exe"),
        ]
        for e in negatives:
            self.assertFalse(detections.matches(e, self.rule["match"]), e.fields)

    def test_not_in_demo_cases(self):
        ids = [f.rule_id for f in detections.run(sample_events()) + detections.run(cloud_events())]
        self.assertNotIn("TV-040", ids)


class RiskScoreTests(unittest.TestCase):
    """The score counts distinct behaviours, not alerts."""

    def _f(self, rule, sev="medium", tactic="Persistence"):
        from datetime import datetime, timezone
        from tracevault.models import Event, Finding
        e = Event(ts=datetime(2026, 1, 1, tzinfo=timezone.utc), source="t", kind="k", host="h", message=rule, raw=rule)
        return Finding(rule_id=rule, title=f"Rule {rule}", severity=sev, tactic=tactic, technique="T0",
                       technique_name="", description="", summary="", ts=e.ts, events=[e])

    def test_repeats_of_one_behaviour_stay_below_high(self):
        r = analysis.risk_assessment([self._f("TV-022") for _ in range(6)])  # the clean-laptop shape
        self.assertLess(r["score"], 50)
        self.assertEqual(r["level"], "medium")
        self.assertTrue(any("Repeats of the same behaviour add little" in x for x in r["reasons"]))

    def test_distinct_behaviours_compound(self):
        same = analysis.risk_assessment([self._f("TV-022") for _ in range(6)])["score"]
        distinct = analysis.risk_assessment([self._f(f"TV-{i:03d}") for i in range(6)])["score"]
        self.assertGreaterEqual(distinct, 50)
        self.assertGreater(distinct, same + 30)

    def test_repeat_bonus_is_capped(self):
        three = analysis.risk_assessment([self._f("TV-022") for _ in range(3)])["score"]
        fifty = analysis.risk_assessment([self._f("TV-022") for _ in range(50)])["score"]
        self.assertEqual(three, fifty)

    def test_single_critical_and_chain_reasons(self):
        r = analysis.risk_assessment([self._f("TV-030", "critical", "Credential Access")])
        self.assertEqual((r["score"], r["level"]), (50, "high"))
        chain = analysis.risk_assessment([self._f("A", "high", "Initial Access"), self._f("B", "high", "Persistence"),
                                          self._f("C", "high", "Exfiltration")])
        self.assertTrue(any("chain from Initial Access to Exfiltration" in x for x in chain["reasons"]))

    def test_no_findings(self):
        self.assertEqual(analysis.risk_assessment([])["score"], 0)

    def test_demo_cases_stay_critical(self):
        self.assertEqual(analysis.analyze(sample_events())["risk"]["level"], "critical")
        self.assertEqual(analysis.analyze(cloud_events())["risk"]["level"], "critical")


class GroupingTests(unittest.TestCase):
    """Exact repeats fold into one finding; anything that differs stays separate."""

    def _svc(self, minute, name, path, host="WS1"):
        rec = {"EventID": 7045, "TimeCreated": f"2026-10-25T05:{minute:02d}:00Z", "Channel": "System",
               "Computer": host, "ServiceName": name, "ImagePath": path}
        return rec

    def _run(self, records):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "system.json"
            p.write_text("\n".join(json.dumps(r) for r in records))
            events = parsers.parse_files([p])
        rule = next(r for r in detections.load_rules() if r["id"] == "TV-022")
        return [f for f in detections.run(events, [rule])]

    def test_identical_repeats_are_grouped(self):
        recs = [self._svc(m, "AgentJob", "C:\\Program Files\\Agent\\job.exe") for m in (1, 7, 30)]
        (f,) = self._run(recs)
        self.assertEqual(f.occurrences, 3)
        self.assertEqual(len(f.events), 3)  # every event kept as evidence
        self.assertEqual((f.ts.minute, f.last_ts.minute), (1, 30))
        d = f.to_dict()
        self.assertEqual((d["occurrences"], d["last_ts"][14:16]), (3, "30"))

    def test_any_difference_keeps_findings_separate(self):
        recs = [self._svc(1, "AgentJob", "C:\\Program Files\\Agent\\job.exe"),
                self._svc(2, "AgentJob", "C:\\Users\\Public\\job.exe"),           # different path
                self._svc(3, "AgentJob", "C:\\Program Files\\Agent\\job.exe", "WS2")]  # different host
        found = self._run(recs)
        self.assertEqual([f.occurrences for f in found], [1, 1, 1])

    def test_multi_event_findings_never_grouped(self):
        # Threshold / followed_by findings already aggregate; grouping leaves them alone.
        found = detections.run(sample_events())
        self.assertEqual([f.rule_id for f in found if f.occurrences > 1], [])

    def test_grouped_finding_shown_once_with_count(self):
        from tracevault import report
        recs = [self._svc(m, "AgentJob", "C:\\Program Files\\Agent\\job.exe") for m in (1, 7)]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "system.json"
            p.write_text("\n".join(json.dumps(r) for r in recs))
            result = analysis.analyze(parsers.parse_files([p]))
        self.assertEqual(result["stats"]["findings"], 1)
        html = report.render(result, [], {"ok": True, "entries": 0, "evidence": [], "problems": []})
        self.assertIn("Identical event repeated 2 times", html)


class ReportTests(unittest.TestCase):
    def setUp(self):
        from tracevault import report
        self.report = report
        self.result = analysis.analyze(cloud_events())
        self.ok = {"ok": True, "entries": 5, "head": "ab" * 32, "evidence": [
            {"file": "okta.json", "expected": "cd" * 32, "actual": "cd" * 32, "ok": True}], "problems": [],
            "checked_at": "2026-10-25T07:00:00+00:00"}

    def test_summary_states_the_facts(self):
        text = " ".join(self.report.executive_summary(self.result, self.ok))
        self.assertIn("16 findings of attacker activity (4 critical, 7 high, 5 medium)", text)
        self.assertIn("between 09:00 and 09:34 UTC on 22 October 2026", text)
        self.assertIn("1 identity appears compromised (priya)", text)
        self.assertIn("the attacker created 1 account (backup-svc)", text)
        self.assertIn("External address involved: 203.0.113.80. Consider blocking it", text)
        self.assertIn("custody ledger (5 entries) is intact", text)

    def test_no_attack_and_failed_integrity_wording(self):
        quiet = analysis.analyze([e for e in sample_events() if "alice" == e.user])
        bad = {**self.ok, "ok": False, "problems": ["Evidence x.log hash changed since acquisition"]}
        text = " ".join(self.report.executive_summary(quiet, bad))
        self.assertIn("found no attacker activity", text)
        self.assertIn("WARNING: the integrity check failed", text)
        html = self.report.render(quiet, [], bad)
        self.assertIn("Integrity check failed", html)
        self.assertIn("hash changed since acquisition", html)

    def test_attacker_content_is_escaped(self):
        evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
        for e in self.result["timeline"]:
            e["message"] = evil
            e["host"] = evil
        for f in self.result["findings"]:
            f["summary"] = evil
        html = self.report.render(self.result, [], self.ok)
        self.assertNotIn("<script>alert(1)", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_all_sections_present(self):
        html = self.report.render(self.result, [], self.ok)
        for anchor in ("summary", "story", "people", "attack", "findings", "review", "custody", "method"):
            self.assertIn(f'id="{anchor}"', html)
        self.assertIn("Page \" counter(page)", html)  # page numbers when printed


class CollectionTests(unittest.TestCase):
    """ingest-collection: verify a collector folder against its manifest, then ingest it."""

    RECORDS = [
        {"EventID": 4625, "TimeCreated": "2026-10-25T05:00:01.000000Z", "Channel": "Security",
         "Computer": "WS9", "TargetUserName": "admin", "IpAddress": "203.0.113.9", "LogonType": "3"},
        {"EventID": 1102, "TimeCreated": "2026-10-25T05:10:00.123456Z", "Channel": "Security",
         "Computer": "WS9", "SubjectUserName": "mallory"},
    ]

    def setUp(self):
        from tracevault.custody import sha256_file
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.folder = self.root / "TraceVault-WS9"
        self.folder.mkdir()
        data = self.folder / "WS9_security.jsonl"
        data.write_text("\n".join(json.dumps(r) for r in self.RECORDS) + "\n", encoding="utf-8")
        self.manifest = {
            "collector": "TraceVault Windows collector", "version": "0.2.0", "host": "WS9",
            "collected_by_account": "CORP\\responder", "elevated": True, "examiner": "J. Doe",
            "window": {"since": "2026-10-24T05:00:00.000000Z", "until": "2026-10-25T06:00:00.000000Z"},
            "files": [{"name": data.name, "channel": "Security", "format": "jsonl", "events": 2,
                       "sha256": sha256_file(data)}],
            "skipped": [{"channel": "Microsoft-Windows-Sysmon/Operational", "reason": "log not present"}],
        }
        self._write_manifest()
        self.case = Case.create(self.root / "cases", "C-1", examiner="tester")

    def _write_manifest(self):
        # PowerShell 5.1 writes UTF-8 with a BOM by default; make sure that is accepted.
        (self.folder / "manifest.json").write_text("﻿" + json.dumps(self.manifest), encoding="utf-8")

    def tearDown(self):
        for p in self.case.evidence_files():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        self.tmp.cleanup()

    def test_verified_collection_is_ingested_and_logged(self):
        (self.folder / "stray.txt").write_text("not from the collector")
        entry = workflow.ingest_collection(self.case, self.folder, examiner="analyst")
        self.assertEqual(entry["action"], "evidence.collection")
        self.assertEqual(entry["details"]["host"], "WS9")
        self.assertEqual(entry["details"]["unlisted_files_not_ingested"], ["stray.txt"])
        self.assertEqual(sorted(p.name for p in self.case.evidence_files()), ["WS9_security.jsonl", "manifest.json"])
        self.assertTrue(self.case.verify()["ok"])
        result = workflow.analyze_case(self.case, examiner="analyst")
        self.assertEqual(result["stats"]["events"], 2)  # the manifest itself is not parsed as events
        self.assertIn("TV-024", [f["rule_id"] for f in result["findings"]])

    def test_altered_file_blocks_the_whole_collection(self):
        with open(self.folder / "WS9_security.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({**self.RECORDS[0], "IpAddress": "10.0.0.1"}) + "\n")
        with self.assertRaises(IOError) as ctx:
            workflow.ingest_collection(self.case, self.folder, examiner="analyst")
        self.assertIn("SHA-256 differs", str(ctx.exception))
        self.assertEqual(self.case.evidence_files(), [])

    def test_missing_file_and_path_tricks_rejected(self):
        self.manifest["files"].append({"name": "..\\..\\secrets.txt", "sha256": "0" * 64})
        self.manifest["files"].append({"name": "../etc/passwd", "sha256": "0" * 64})
        self.manifest["files"].append({"name": "C:evil.json", "sha256": "0" * 64})
        self.manifest["files"].append({"name": "WS9_system.jsonl", "sha256": "0" * 64})
        self._write_manifest()
        with self.assertRaises(IOError) as ctx:
            workflow.ingest_collection(self.case, self.folder, examiner="analyst")
        msg = str(ctx.exception)
        self.assertEqual(msg.count("invalid file name"), 3)
        self.assertIn("WS9_system.jsonl: listed in the manifest but missing", msg)
        self.assertEqual(self.case.evidence_files(), [])

    def test_not_a_collector_folder(self):
        (self.folder / "manifest.json").write_text(json.dumps({"files": []}))
        with self.assertRaises(ValueError):
            workflow.ingest_collection(self.case, self.folder)

    def test_collector_script_ships_with_matching_version(self):
        from tracevault import __version__
        from tracevault.cli import COLLECTORS
        script = COLLECTORS["windows"].read_text(encoding="utf-8")
        self.assertIn(f"$CollectorVersion = '{__version__}'", script)

    def test_collector_record_shape_parses(self):
        # The exact shape the collector writes: ISO UTC TimeCreated with a Z, Computer, Channel.
        events = parsers.parse_files([self.folder / "WS9_security.jsonl"])
        self.assertEqual([e.kind for e in events], ["auth.failure", "log.cleared"])
        self.assertEqual(events[0].ts.isoformat(), "2026-10-25T05:00:01+00:00")
        self.assertEqual((events[0].host, events[0].user, events[0].src_ip), ("WS9", "admin", "203.0.113.9"))


class IdentityTests(unittest.TestCase):
    def test_canonical_auto_linking(self):
        self.assertEqual(identities.canonical("Priya@Acme.example"), "priya")
        self.assertEqual(identities.canonical("ACME\\priya"), "priya")
        self.assertEqual(identities.canonical("helpdesk$"), "helpdesk$")

    def test_identity_map_merges_and_splits(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "identities.json"
            p.write_text(json.dumps({"Priya Shah": ["priya", "p.shah"], "Sam (vendor)": ["sam@vendor.example"]}))
            m = identities.load_map(p)
        self.assertEqual(identities.canonical("p.shah", m), "Priya Shah")
        self.assertEqual(identities.canonical("priya@acme.example", m), "Priya Shah")  # via auto-stripped "priya"
        self.assertEqual(identities.canonical("sam@vendor.example", m), "Sam (vendor)")
        self.assertEqual(identities.canonical("sam@acme.example", m), "sam")  # a different sam stays separate

    def test_cloud_case_identities(self):
        by_name = {i["identity"]: i for i in analysis.analyze(cloud_events())["identities"]}
        priya = by_name["priya"]
        self.assertEqual(priya["status"], "compromised")
        self.assertEqual(set(priya["aliases"]), {"priya", "priya@acme.example"})
        self.assertEqual(len(priya["systems"]), 3)
        self.assertEqual(by_name["backup-svc"]["status"], "created")
        self.assertEqual(by_name["marcus"]["status"], "targeted")
        self.assertNotIn("root", by_name)  # root use is a posture finding, not attacker activity

    def test_host_case_identities(self):
        by_name = {i["identity"]: i["status"] for i in analysis.analyze(sample_events())["identities"]}
        self.assertEqual(by_name["deploy"], "compromised")
        self.assertEqual(by_name["administrator"], "compromised")
        self.assertEqual(by_name["sysbackup"], "created")
        self.assertEqual(by_name["helpdesk$"], "created")
        self.assertEqual(by_name["admin"], "targeted")


class PostureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = analysis.analyze(cloud_events())

    def test_root_use_is_posture(self):
        root = next(f for f in self.result["findings"] if f["rule_id"] == "TV-201")
        self.assertEqual(root["category"], "posture")
        self.assertEqual(self.result["stats"]["posture_findings"], 1)
        self.assertNotIn("Privilege Escalation - from 08:30", " ".join(self.result["narrative"]))

    def test_attacker_window_and_iocs_exclude_benign_activity(self):
        self.assertTrue(self.result["stats"]["dwell"][0].startswith("2026-10-22T09:00:05"))
        self.assertEqual([x["value"] for x in self.result["iocs"]["ips"]], ["203.0.113.80"])

    def test_impossible_travel_marks_normal_login_as_context(self):
        travel = next(f for f in self.result["findings"] if f["rule_id"] == "TV-214")
        self.assertEqual(len(travel["context_event_ids"]), 1)
        self.assertEqual(travel["context_event_ids"][0], travel["event_ids"][0])


class AnalysisTests(unittest.TestCase):
    def test_risk_score_bounds(self):
        self.assertEqual(analysis.risk_score([]), 0)
        result = analysis.analyze(sample_events())
        self.assertGreaterEqual(result["risk"]["score"], 80)
        self.assertEqual(result["risk"]["level"], "critical")
        json.dumps(result)  # must be serialisable

    def test_iocs_mark_external(self):
        result = analysis.analyze(sample_events())
        ips = {x["value"]: x["external"] for x in result["iocs"]["ips"]}
        self.assertTrue(ips["203.0.113.45"])
        self.assertFalse(ips["10.0.0.15"])


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.case = Case.create(self.root, "T-1", title="test", examiner="tester")
        for f in sorted(SAMPLES.iterdir()):
            self.case.ingest(f, examiner="tester")

    def tearDown(self):
        for p in self.case.evidence_files():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
        self.tmp.cleanup()

    def test_clean_case_verifies(self):
        v = self.case.verify()
        self.assertTrue(v["ok"], v["problems"])
        self.assertEqual(v["entries"], 4)

    def test_evidence_tamper_detected(self):
        target = self.case.evidence_dir / "web-01_auth.log"
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        with open(target, "a") as fh:
            fh.write("Oct 21 04:00:00 web-01 sshd[1]: nothing to see here\n")
        v = self.case.verify()
        self.assertFalse(v["ok"])
        self.assertTrue(any("hash changed" in p for p in v["problems"]))

    def test_ledger_edit_detected(self):
        lines = self.case.ledger_path.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["actor"] = "someone-else"
        lines[1] = json.dumps(entry)
        self.case.ledger_path.write_text("\n".join(lines) + "\n")
        v = self.case.verify()
        self.assertFalse(v["ok"])
        self.assertTrue(any("modified" in p for p in v["problems"]))

    def test_ledger_deletion_detected(self):
        lines = self.case.ledger_path.read_text().splitlines()
        del lines[1]
        self.case.ledger_path.write_text("\n".join(lines) + "\n")
        self.assertFalse(self.case.verify()["ok"])

    def test_unlogged_evidence_detected(self):
        (self.case.evidence_dir / "planted.log").write_text("x")
        v = self.case.verify()
        self.assertTrue(any("never logged" in p for p in v["problems"]))

    def test_invalid_case_id_rejected(self):
        for bad in ("../escape", "a/b", "a\\b", ".hidden", "", "CASE-1\n", "CON", "nul.txt", "x" * 65):
            with self.assertRaises(ValueError, msg=repr(bad)):
                Case(self.root, bad)
        self.assertEqual(Case(self.root, "IR-2026.014_a").dir.parent, Path(os.path.realpath(self.root)))

    def test_full_workflow(self):
        result = workflow.analyze_case(self.case, examiner="tester")
        self.assertTrue((self.case.dir / "report.html").exists())
        self.assertGreater(result["stats"]["findings"], 10)
        actions = [e["action"] for e in self.case.entries()]
        self.assertEqual(actions[-2:], ["analysis.run", "report.export"])
        self.assertTrue(self.case.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
