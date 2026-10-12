"""Parser + pipeline smoke test (format fixtures only - see tests/fixtures/README.txt)."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from idspipe import db  # noqa: E402
from idspipe.audit import audit  # noqa: E402
from idspipe.config import load_config  # noqa: E402
from idspipe.engine import Pipeline  # noqa: E402
from idspipe.parsers import parse_snort_fast, parse_snort_json, parse_suricata  # noqa: E402

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class T(unittest.TestCase):
    def test_parsers(self):
        with open(f"{FX}/eve_sample.json") as f:
            kinds = [parse_suricata(l)[0] for l in f]
        self.assertEqual(kinds, ["alert", "alert", "alert", "flow", "meta"])
        with open(f"{FX}/snort_alert_json_sample.txt") as f:
            k, ev = parse_snort_json(f.readline())
        self.assertEqual((k, ev.sid, ev.severity, ev.src_ip), ("alert", 1000010, 2, "172.16.0.1"))
        with open(f"{FX}/snort_fast_sample.txt") as f:
            for l in f:
                k, ev = parse_snort_fast(l, {"snort": {"fast_year": 2017}})
                self.assertEqual((ev.sid, ev.dst_port, ev.proto), (1000010, 80, "TCP"))

    def test_pipeline_counts(self):
        tmp = tempfile.mkdtemp()
        try:
            cfg = load_config()
            cfg["paths"].update(db=f"{tmp}/t.db", suricata_eve=f"{FX}/eve_sample.json",
                                snort_alerts=f"{FX}/snort_alert_json_sample.txt",
                                notifications_log=f"{tmp}/n.log", reports_dir=tmp)
            cfg["notifications"]["console"] = False
            p = Pipeline(cfg, reset=True)
            p.run_once()
            rows = audit(cfg, p.conn)
            self.assertTrue(all(r["ok"] for r in rows), rows)
            self.assertEqual(p.conn.execute("SELECT COUNT(*) c FROM events WHERE engine='suricata'").fetchone()["c"], 3)
            self.assertEqual(p.conn.execute("SELECT COUNT(*) c FROM events WHERE engine='snort'").fetchone()["c"], 2)
            inc = p.conn.execute("SELECT * FROM incidents").fetchall()
            self.assertEqual(len(inc), 1)                       # same src/dst pair => one incident
            self.assertEqual(inc[0]["engines"], "snort,suricata")
            # resume: second run must not duplicate anything
            p2 = Pipeline(cfg)
            p2.run_once()
            self.assertEqual(p2.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"], 5)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
