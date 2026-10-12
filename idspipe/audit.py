"""Reconciliation: proves the numbers on the dashboard equal what Snort/Suricata actually wrote.
raw alert lines in file  ==  events in DB  ==  sum(group counts)  ==  sum(incident event counts)."""
from .parsers import count_raw_alerts


def audit(cfg, conn):
    sources = [("suricata", cfg["paths"]["suricata_eve"], "eve"),
               ("snort", cfg["paths"]["snort_alerts"],
                "snort_fast" if cfg["snort"].get("format", "json") == "fast" else "snort_json")]
    rows = []
    for eng, path, fmt in sources:
        raw = count_raw_alerts(path, fmt)
        ev = conn.execute("SELECT COUNT(*) c FROM events WHERE engine=?", (eng,)).fetchone()["c"]
        gr = conn.execute("SELECT COALESCE(SUM(count),0) c FROM groups WHERE engine=?", (eng,)).fetchone()["c"]
        rows.append({"engine": eng, "raw_file_alerts": raw, "events_in_db": ev, "sum_group_counts": gr,
                     "ok": raw == ev == gr})
    total_ev = conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    inc = conn.execute("SELECT COALESCE(SUM(event_count),0) c FROM incidents").fetchone()["c"]
    rows.append({"engine": "ALL (incl. ml)", "raw_file_alerts": None, "events_in_db": total_ev,
                 "sum_group_counts": conn.execute("SELECT COALESCE(SUM(count),0) c FROM groups").fetchone()["c"],
                 "sum_incident_counts": inc, "ok": total_ev == inc})
    return rows


def print_audit(rows):
    print("\n=== Reconciliation (nothing dropped, nothing invented) ===")
    for r in rows:
        print(f"{r['engine']:<16} raw_file={r['raw_file_alerts']!s:<9} db_events={r['events_in_db']:<9} "
              f"group_sum={r['sum_group_counts']:<9} " + (f"incident_sum={r['sum_incident_counts']:<9} " if 'sum_incident_counts' in r else "")
              + ("PASS" if r["ok"] else "MISMATCH"))
