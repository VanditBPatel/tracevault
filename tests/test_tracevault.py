import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tracevault import analysis, detections, parsers, workflow  # noqa: E402
from tracevault.custody import Case  # noqa: E402

SAMPLES = ROOT / "samples" / "case-001"


def sample_events():
    return parsers.parse_files(sorted(SAMPLES.iterdir()), year=2026)


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
