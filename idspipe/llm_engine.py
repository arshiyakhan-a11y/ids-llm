"""Stage 8 - AI / LLM engine (OpenAI): analysis, ranking, explanation, risk classification, actions.
The LLM only sees summaries built from REAL Snort/Suricata alerts stored in the DB."""
import json
import os
import time

from . import db
from .notifier import Notifier
from .util import fmt_ts

SYSTEM = """You are a senior SOC analyst. You receive a JSON summary of ONE correlated incident built from
real Snort and/or Suricata alerts from a packet capture (the two engines are already merged into one incident list). Analyse it and answer with a single JSON object:
{
 "summary": "2-3 sentence plain-language summary",
 "attack_type": "short label, e.g. Port scan / Brute force / DoS / Web attack / Botnet / Benign-noise",
 "explanation": "why the alerts indicate this, citing the signatures and counts you were given",
 "risk_class": "critical|high|medium|low|false_positive_likely",
 "priority": <integer 1 (lowest) to 10 (most urgent)>,
 "confidence": <0.0-1.0>,
 "mitre_attack": ["T1046", ...],
 "recommended_actions": ["concrete step 1", "concrete step 2", "..."],
 "false_positive_notes": "what could make this benign, or empty string"
}
Use only the data provided; do not invent IPs, counts or signatures. If evidence is thin, say so and lower confidence."""


def incident_context(conn, inc):
    q = conn.execute
    sigs = [dict(r) for r in q(
        "SELECT engine, signature, category, MAX(severity) severity, COUNT(*) alerts FROM events "
        "WHERE incident_id=? GROUP BY engine, sid ORDER BY alerts DESC LIMIT 12", (inc["id"],))]
    ports = [dict(r) for r in q(
        "SELECT dst_port, COUNT(*) alerts FROM events WHERE incident_id=? GROUP BY dst_port ORDER BY alerts DESC LIMIT 8",
        (inc["id"],))]
    roles = {r["ip"]: r["role"] for r in q("SELECT ip, role FROM assets WHERE ip IN (?,?)", (inc["src_ip"], inc["dst_ip"]))}
    sev = {0: "info", 1: "low", 2: "medium", 3: "high"}
    for s in sigs:
        s["severity"] = sev.get(s["severity"], "low")
    return {"incident_id": inc["id"], "src_ip": inc["src_ip"], "src_role": roles.get(inc["src_ip"], ""),
            "dst": inc["dst_ip"], "dst_role": roles.get(inc["dst_ip"], ""),
            "first_alert_utc": fmt_ts(inc["first_ts"]), "last_alert_utc": fmt_ts(inc["last_ts"]),
            "duration_sec": round(inc["last_ts"] - inc["first_ts"], 1), "total_alerts": inc["event_count"],
            "alert_groups": inc["group_count"], "engines": inc["engines"], "computed_risk_score": inc["risk_score"],
            "top_signatures": sigs, "top_destination_ports": ports}


class LLMEngine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.l = cfg.get("llm", {})
        self.notifier = Notifier(cfg)
        self.client = None

    def available(self):
        return bool(self.l.get("enabled", True)) and bool(os.getenv("OPENAI_API_KEY"))

    def _client(self):
        if self.client is None:
            from openai import OpenAI
            self.client = OpenAI()   # reads OPENAI_API_KEY from the environment
        return self.client

    def call(self, system, user):
        r = self._client().chat.completions.create(
            model=self.l.get("model", "gpt-4o-mini"), temperature=float(self.l.get("temperature", 0.2)),
            response_format={"type": "json_object"},
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
        return json.loads(r.choices[0].message.content)

    def _analyze_one(self, conn, inc):
        ctx = incident_context(conn, inc)
        try:
            out = self.call(SYSTEM, json.dumps(ctx))
            conn.execute(
                "UPDATE incidents SET llm_status='done', llm_json=?, llm_risk=?, llm_priority=?, llm_ts=?,"
                " llm_event_count=?, llm_error=NULL WHERE id=?",
                (json.dumps(out), str(out.get("risk_class", "")), int(out.get("priority", 0) or 0), time.time(),
                 inc["event_count"], inc["id"]))
            if str(out.get("risk_class", "")).lower() in ("critical", "high"):
                self.notifier.emit(conn, inc["id"], str(out["risk_class"]).lower(),
                                   f"LLM verdict for incident #{inc['id']}: {out.get('attack_type', '?')} - {out.get('summary', '')}")
            conn.commit()
            return 1
        except Exception as e:
            conn.execute("UPDATE incidents SET llm_status='error', llm_attempts=llm_attempts+1, llm_error=? WHERE id=?",
                         (str(e)[:300], inc["id"]))
            print(f"[llm] incident {inc['id']} failed: {e}")
            conn.commit()
            return 0

    def analyze_pending(self, conn, settle=None, limit=None):
        """Analyse incidents that are new or grew a lot. Returns number analysed."""
        settle = self.l.get("settle_sec", 15) if settle is None else settle
        limit = limit or self.l.get("max_incidents_per_cycle", 5)
        rows = conn.execute(
            "SELECT * FROM incidents WHERE risk_score>=? AND (? - updated_wall) >= ? AND ("
            " (llm_status IN ('pending','error') AND llm_attempts<?) OR"
            " (llm_status='done' AND event_count > 2*llm_event_count AND event_count > llm_event_count+50))"
            " ORDER BY risk_score DESC LIMIT ?",
            (self.l.get("min_risk_score", 30), time.time(), settle, self.l.get("max_attempts", 3), limit)).fetchall()
        n = 0
        for inc in rows:
            n += self._analyze_one(conn, inc)
        return n


def analyze_top(cfg, conn, top_n=20, min_risk=None):
    """Rank ALL unified incidents (Snort + Suricata) by risk score and run the LLM on the top N not yet analysed."""
    eng = LLMEngine(cfg)
    if not eng.available():
        print("[llm] skipped (no OPENAI_API_KEY or llm.enabled=false)")
        return 0
    lo = cfg["llm"].get("min_risk_score", 30) if min_risk is None else min_risk
    ids = [r["id"] for r in conn.execute(
        "SELECT id FROM incidents WHERE risk_score>=? ORDER BY risk_score DESC, event_count DESC LIMIT ?", (lo, top_n))]
    done = 0
    for iid in ids:
        conn.execute("UPDATE incidents SET llm_status='pending', llm_attempts=0 WHERE id=? AND llm_status<>'done'", (iid,))
    conn.commit()
    for i in range(0, len(ids), 5):
        chunk = ids[i:i + 5]
        q = ",".join("?" * len(chunk))
        rows = conn.execute(f"SELECT * FROM incidents WHERE id IN ({q}) AND llm_status<>'done'", chunk).fetchall()
        for inc in rows:
            n = eng._analyze_one(conn, inc)
            done += n
    return done


def llm_worker(cfg, stop_event):
    """Background thread for live mode."""
    eng = LLMEngine(cfg)
    if not eng.available():
        print("[llm] OPENAI_API_KEY not set or llm.enabled=false -> LLM stage idle (pipeline continues without it).")
        return
    conn = db.connect(cfg["paths"]["db"])
    while not stop_event.is_set():
        try:
            eng.analyze_pending(conn)
        except Exception as e:
            print(f"[llm] worker error: {e}")
        stop_event.wait(float(cfg["llm"].get("interval_sec", 20)))
