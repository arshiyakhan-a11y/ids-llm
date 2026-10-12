"""Output: Markdown report. All numbers come from the DB; the LLM only writes the narrative."""
import json
import os
import time

from .audit import audit
from .util import fmt_ts, SEV_LABEL

EXEC_SYSTEM = ("You are a SOC lead writing an executive summary of a replayed network-attack capture analysed by Snort and "
               "Suricata. Input: JSON list of the top incidents with their analyses. Output JSON: "
               '{"executive_summary": "<=150 words", "top_priorities": ["..."], "overall_posture": "..."}. '
               "Use only the data provided.")


def generate_report(cfg, conn, use_llm=True):
    from .llm_engine import LLMEngine
    q = lambda sql, *a: conn.execute(sql, a).fetchall()
    L = ["# IDS Pipeline Report", f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')}_", ""]
    L += ["## 1. Alert statistics (raw Snort / Suricata counts)", "", "| Engine | Alerts | Groups | High | Medium | Low/Info |", "|---|---|---|---|---|---|"]
    for r in q("SELECT engine, COUNT(*) n, SUM(severity=3) h, SUM(severity=2) m, SUM(severity<=1) l FROM events GROUP BY engine"):
        g = q("SELECT COUNT(*) c FROM groups WHERE engine=?", r["engine"])[0]["c"]
        L.append(f"| {r['engine']} | {r['n']} | {g} | {r['h']} | {r['m']} | {r['l']} |")
    L += ["", "### Reconciliation", "", "| Source | Raw file alerts | DB events | Group sum | Status |", "|---|---|---|---|---|"]
    for a in audit(cfg, conn):
        L.append(f"| {a['engine']} | {a['raw_file_alerts']} | {a['events_in_db']} | {a['sum_group_counts']} | {'PASS' if a['ok'] else 'MISMATCH'} |")
    L += ["", "## 2. Top signatures", "", "| Engine | Signature | Alerts |", "|---|---|---|"]
    for r in q("SELECT engine, signature, COUNT(*) n FROM events GROUP BY engine, sid ORDER BY n DESC LIMIT 15"):
        L.append(f"| {r['engine']} | {r['signature']} | {r['n']} |")
    L += ["", "## 3. Top incidents", "", "| # | Source | Target | Alerts | Engines | Risk | LLM class | First alert |", "|---|---|---|---|---|---|---|---|"]
    top = q("SELECT * FROM incidents ORDER BY COALESCE(llm_priority,0) DESC, risk_score DESC LIMIT 15")
    for r in top:
        L.append(f"| {r['id']} | {r['src_ip']} | {r['dst_ip']} | {r['event_count']} | {r['engines']} | {r['risk_score']} ({r['risk_label']}) | {r['llm_risk'] or '-'} | {fmt_ts(r['first_ts'])} |")

    analysed = [r for r in top if r["llm_json"]]
    eng = LLMEngine(cfg)
    if use_llm and eng.available() and analysed:
        try:
            ex = eng.call(EXEC_SYSTEM, json.dumps([{"incident": r["id"], "src": r["src_ip"], "dst": r["dst_ip"], "alerts": r["event_count"],
                                                    "analysis": json.loads(r["llm_json"])} for r in analysed[:10]]))
            L += ["", "## 4. Executive summary (LLM)", "", ex.get("executive_summary", ""), "", f"**Posture:** {ex.get('overall_posture', '')}", ""]
            L += [f"- {p}" for p in ex.get("top_priorities", [])]
        except Exception as e:
            L += ["", f"_Executive summary unavailable: {e}_"]
    L += ["", "## 5. Incident analyses & recommended actions (LLM)"]
    for r in analysed[:10]:
        j = json.loads(r["llm_json"])
        L += ["", f"### Incident #{r['id']}: {j.get('attack_type', '')} ({j.get('risk_class', '')}, priority {j.get('priority', '')})",
              f"{r['src_ip']} -> {r['dst_ip']} | {r['event_count']} alerts", "", j.get("summary", ""), "", j.get("explanation", ""), "",
              "**Recommended actions**"] + [f"- {a}" for a in j.get("recommended_actions", [])]
        if j.get("mitre_attack"):
            L.append(f"\n**MITRE ATT&CK:** {', '.join(j['mitre_attack'])}")
    if not analysed:
        L += ["", "_No LLM analyses yet (set OPENAI_API_KEY and let the LLM stage run)._"]
    os.makedirs(cfg["paths"]["reports_dir"], exist_ok=True)
    path = os.path.join(cfg["paths"]["reports_dir"], f"report_{time.strftime('%Y%m%d_%H%M%S')}.md")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    conn.execute("INSERT INTO reports(wall,path) VALUES(?,?)", (time.time(), path))
    conn.commit()
    return path
