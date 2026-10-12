"""Stage 6 - Alert aggregation: group similar / duplicate alerts into summaries.
Key = (engine, signature id, src, dst). Alerts of that key closer than `window` seconds
are consolidated into ONE group with a counter. Nothing is dropped: the sum of all group
counts always equals the number of stored events (checked by the audit)."""


class Aggregator:
    def __init__(self, window=60):
        self.window = window
        self.by_key = {}      # key -> [group dict, ...]
        self.by_id = {}       # group id -> group dict
        self.dirty = set()

    def load(self, conn):
        """Resume after restart."""
        for r in conn.execute("SELECT * FROM groups"):
            g = dict(r)
            self.by_id[g["id"]] = g
            self.by_key.setdefault((g["engine"], g["sid"], g["src_ip"], g["dst_ip"]), []).append(g)

    def add(self, conn, ev, incident_id):
        """Add event to a group (create if needed). Returns group id."""
        key = (ev.engine, ev.sid, ev.src_ip, ev.dst_ip)
        lst = self.by_key.setdefault(key, [])
        for g in lst:
            if g["first_ts"] - self.window <= ev.ts <= g["last_ts"] + self.window:
                g["first_ts"] = min(g["first_ts"], ev.ts)
                g["last_ts"] = max(g["last_ts"], ev.ts)
                g["count"] += 1
                g["last_dst_port"] = ev.dst_port
                g["severity"] = max(g["severity"], ev.severity)
                g["incident_id"] = incident_id
                self.dirty.add(g["id"])
                return g["id"]
        cur = conn.execute(
            "INSERT INTO groups(engine,sid,signature,category,severity,src_ip,dst_ip,last_dst_port,"
            "first_ts,last_ts,count,incident_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev.engine, ev.sid, ev.signature, ev.category, ev.severity, ev.src_ip, ev.dst_ip,
             ev.dst_port, ev.ts, ev.ts, 1, incident_id))
        g = {"id": cur.lastrowid, "engine": ev.engine, "sid": ev.sid, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
             "first_ts": ev.ts, "last_ts": ev.ts, "count": 1, "last_dst_port": ev.dst_port,
             "severity": ev.severity, "incident_id": incident_id}
        lst.append(g)
        self.by_id[g["id"]] = g
        return g["id"]

    def reassign(self, conn, old_incident, new_incident):
        """Called when two incidents are merged."""
        self.flush(conn)
        conn.execute("UPDATE groups SET incident_id=? WHERE id IN (SELECT id FROM groups WHERE incident_id=?)",
                     (new_incident, old_incident))
        for g in self.by_id.values():
            if g["incident_id"] == old_incident:
                g["incident_id"] = new_incident

    def flush(self, conn):
        for gid in self.dirty:
            g = self.by_id[gid]
            conn.execute("UPDATE groups SET first_ts=?,last_ts=?,count=?,last_dst_port=?,severity=?,incident_id=? WHERE id=?",
                         (g["first_ts"], g["last_ts"], g["count"], g["last_dst_port"], g["severity"],
                          g["incident_id"], gid))
        self.dirty.clear()
