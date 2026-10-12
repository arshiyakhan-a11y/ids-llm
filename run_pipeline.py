#!/usr/bin/env python3
"""IDS -> LLM pipeline CLI.

  python run_pipeline.py run            # live: tail Snort+Suricata logs forever (Ctrl-C to stop)
  python run_pipeline.py run --once     # process the logs that exist now, run LLM, write report, audit, exit
  python run_pipeline.py audit          # reconcile raw alert counts vs database
  python run_pipeline.py report         # generate a Markdown report from the database
  python run_pipeline.py train-ml --eve logs/suricata/eve.json   # optional AI detector (benign capture)
"""
import argparse
import sys

from idspipe import db
from idspipe.audit import audit, print_audit
from idspipe.config import load_config
from idspipe.engine import Pipeline
from idspipe.llm_engine import LLMEngine
from idspipe.report import generate_report


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", default="run", choices=["run", "audit", "report", "train-ml", "llm"])
    ap.add_argument("--config", default=None)
    ap.add_argument("--once", action="store_true", help="process existing logs then exit")
    ap.add_argument("--reset", action="store_true", help="delete the database first (re-ingest from the start)")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--top", type=int, default=0, help="llm: analyse the top-N ranked incidents")
    ap.add_argument("--eve", help="eve.json for train-ml")
    ap.add_argument("--suricata", help="override path to eve.json")
    ap.add_argument("--snort", help="override path to Snort alert file")
    a = ap.parse_args()

    cfg = load_config(a.config)
    if a.suricata:
        cfg["paths"]["suricata_eve"] = a.suricata
    if a.snort:
        cfg["paths"]["snort_alerts"] = a.snort
    if a.no_llm:
        cfg["llm"]["enabled"] = False

    if a.command == "train-ml":
        from idspipe.detection import train
        train(a.eve or cfg["paths"]["suricata_eve"], cfg["paths"]["ml_model"])
        return
    if a.command == "llm":
        from idspipe.llm_engine import analyze_top
        conn = db.connect(cfg["paths"]["db"])
        n = analyze_top(cfg, conn, a.top or int(cfg["llm"].get("max_incidents_once", 30)))
        print(f"[llm] analysed {n} incident(s)")
        print("Report:", generate_report(cfg, conn, use_llm=True))
        return
    if a.command == "audit":
        conn = db.connect(cfg["paths"]["db"])
        rows = audit(cfg, conn)
        print_audit(rows)
        sys.exit(0 if all(r["ok"] for r in rows) else 1)
    if a.command == "report":
        conn = db.connect(cfg["paths"]["db"])
        print("Report:", generate_report(cfg, conn, use_llm=not a.no_llm))
        return

    p = Pipeline(cfg, reset=a.reset)
    if a.once:
        p.run_once()
        eng = LLMEngine(cfg)
        if eng.available():
            from idspipe.llm_engine import analyze_top
            total = analyze_top(cfg, p.conn, int(cfg["llm"].get("max_incidents_once", 30)))
            print(f"[llm] analysed {total} incident(s) (top-ranked by risk score)")
        else:
            print("[llm] skipped (no OPENAI_API_KEY or disabled)")
        print("Report:", generate_report(cfg, p.conn, use_llm=eng.available()))
        rows = audit(cfg, p.conn)
        print_audit(rows)
    else:
        p.run_forever()


if __name__ == "__main__":
    main()
