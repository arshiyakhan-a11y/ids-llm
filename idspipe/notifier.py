"""Output: real-time notifications (console, log file, DB for the dashboard, optional webhook)."""
import json
import time
import urllib.request

from .util import fmt_ts

COL = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}


class Notifier:
    def __init__(self, cfg):
        n = cfg.get("notifications", {})
        self.min_risk = float(n.get("min_risk_score", 60))
        self.webhook = n.get("webhook_url") or ""
        self.console = bool(n.get("console", True))
        self.log_path = cfg["paths"]["notifications_log"]

    def emit(self, conn, incident_id, level, message):
        conn.execute("INSERT INTO notifications(wall,incident_id,level,message) VALUES(?,?,?,?)",
                     (time.time(), incident_id, level, message))
        try:
            with open(self.log_path, "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level.upper()}] {message}\n")
        except OSError:
            pass
        if self.console:
            print(f"{COL.get(level, '')}[{level.upper()}]\033[0m {message}", flush=True)
        if self.webhook:
            try:
                req = urllib.request.Request(self.webhook, data=json.dumps({"text": f"[{level.upper()}] {message}"}).encode(),
                                             headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).read()
            except Exception as e:  # never let a webhook failure stop the pipeline
                print(f"[notify] webhook failed: {e}")

    def check(self, conn):
        rows = conn.execute("SELECT * FROM incidents WHERE notified=0 AND risk_score>=?", (self.min_risk,)).fetchall()
        for r in rows:
            msg = (f"Incident #{r['id']}: {r['src_ip']} -> {r['dst_ip']} | {r['event_count']} alerts "
                   f"({r['engines']}) | {r['top_signature']} | risk {r['risk_score']} | {fmt_ts(r['first_ts'])}")
            self.emit(conn, r["id"], r["risk_label"], msg)
            conn.execute("UPDATE incidents SET notified=1 WHERE id=?", (r["id"],))
