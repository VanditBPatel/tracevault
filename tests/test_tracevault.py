import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tracevault import analysis, detections, identities, parsers, workflow  # noqa: E402
from tracevault.custody import Case  # noqa: E402

SAMPLES = ROOT / "samples" / "case-001"
CLOUD = ROOT / "samples" / "case-002"


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
        login = next(e for e in events if e.user == "priya@acme.io" and e.kind == "auth.success")
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
                w.writerow(["1", "2026-10-22T09:14:05", "ExchangeAdmin", "New-InboxRule", "priya@acme.io", json.dumps(record)])
            self.assertEqual(parsers.detect_format(p), "m365")
            (e,) = parsers.parse_file(p)
            self.assertEqual(e.fields["operation"], "New-InboxRule")

    def test_okta_mfa_kinds_and_geo(self):
        events = parsers.parse_okta(CLOUD / "okta_system_log.json")
        kinds = [e.kind for e in events]
        self.assertEqual(kinds.count("mfa.push"), 6)
        self.assertEqual(kinds.count("mfa.deny"), 4)
        last = [e for e in events if e.kind == "auth.success" and e.user == "priya@acme.io"][-1]
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
                self.assertNotIn("marcus@acme.io", f.entities()["users"], f.title)

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


class IdentityTests(unittest.TestCase):
    def test_canonical_auto_linking(self):
        self.assertEqual(identities.canonical("Priya@Acme.io"), "priya")
        self.assertEqual(identities.canonical("ACME\\priya"), "priya")
        self.assertEqual(identities.canonical("helpdesk$"), "helpdesk$")

    def test_identity_map_merges_and_splits(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "identities.json"
            p.write_text(json.dumps({"Priya Shah": ["priya", "p.shah"], "Sam (vendor)": ["sam@vendor.example"]}))
            m = identities.load_map(p)
        self.assertEqual(identities.canonical("p.shah", m), "Priya Shah")
        self.assertEqual(identities.canonical("priya@acme.io", m), "Priya Shah")  # via auto-stripped "priya"
        self.assertEqual(identities.canonical("sam@vendor.example", m), "Sam (vendor)")
        self.assertEqual(identities.canonical("sam@acme.io", m), "sam")  # a different sam stays separate

    def test_cloud_case_identities(self):
        by_name = {i["identity"]: i for i in analysis.analyze(cloud_events())["identities"]}
        priya = by_name["priya"]
        self.assertEqual(priya["status"], "compromised")
        self.assertEqual(set(priya["aliases"]), {"priya", "priya@acme.io"})
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
        with self.assertRaises(ValueError):
            Case(self.root, "../escape")

    def test_full_workflow(self):
        result = workflow.analyze_case(self.case, examiner="tester")
        self.assertTrue((self.case.dir / "report.html").exists())
        self.assertGreater(result["stats"]["findings"], 10)
        actions = [e["action"] for e in self.case.entries()]
        self.assertEqual(actions[-2:], ["analysis.run", "report.export"])
        self.assertTrue(self.case.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
