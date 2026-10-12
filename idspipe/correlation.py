"""Stage 5 - Alert correlation: link related alerts (same src/dst, close in time) into incidents,
reduce noise and attach asset context (roles). Also computes the risk score."""
import json
import math
import time
from collections import Counter


NOISE_PREFIXES = ("SURICATA ",)   # Suricata decoder/stream/app-layer events: checksum errors, bad ethertype, ...


def is_noise(signature):
    """Engine housekeeping events (not attacks). They are kept and counted, but never rank as high risk."""
    return str(signature or "").upper().startswith(NOISE_PREFIXES)


def risk_label(score):
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"


class Incident:
    def __init__(self, row):
        self.id = row["id"]
        self.src, self.dst = row["src_ip"], row["dst_ip"]
        self.first, self.last = row["first_ts"], row["last_ts"]
        self.count = row["event_count"]
        self.groups = row["group_count"]
        self.engines = set(filter(None, (row["engines"] or "").split(",")))
        self.sigs = Counter()
        self.cats = Counter()
        self.max_sev = row["max_severity"]
        self.dsts = set([row["dst_ip"]])
        self.dst_role = ""
        self.score = row["risk_score"] or 0
        self.label = row["risk_label"] or "low"

    def update_risk(self):
        noise = sum(c for sg, c in self.sigs.items() if is_noise(sg))
        real = max(0, self.count - noise)
        if real == 0:                                     # only decoder/stream noise -> always low
            self.score = round(min(30.0, 5 * self.max_sev + 4 * math.log2(1 + self.count)), 1)
            self.label = risk_label(self.score)
            return
        real_sigs = sum(1 for sg in self.sigs if not is_noise(sg))
        s = 15 * self.max_sev
        s += min(30, 10 * math.log2(1 + real))
        s += min(15, 3 * real_sigs)
        if len(self.engines - {"ml"}) >= 2:
            s += 10
        if self.dst_role and any(k in self.dst_role.lower() for k in ("server", "controller", "dns")):
            s += 5
        self.score = round(min(100.0, s), 1)
        self.label = risk_label(self.score)


class Correlator:
    def __init__(self, window=300, key_mode="pair"):
        self.window = window
        self.key_mode = key_mode
        self.by_key = {}
        self.by_id = {}
        self.dirty = set()

    def _key(self, ev):
        return (ev.src_ip, ev.dst_ip) if self.key_mode == "pair" else (ev.src_ip,) if self.key_mode == "src" else (ev.dst_ip,)

    def load(self, conn):
        for r in conn.execute("SELECT * FROM incidents"):
            inc = Incident(r)
            self.by_id[inc.id] = inc
            self.by_key.setdefault(self._rowkey(r), []).append(inc)
        for r in conn.execute("SELECT incident_id, signature, COUNT(*) c FROM events GROUP BY incident_id, signature"):
            if r["incident_id"] in self.by_id:
                self.by_id[r["incident_id"]].sigs[r["signature"]] += r["c"]

    def _rowkey(self, r):
        return (r["src_ip"], r["dst_ip"]) if self.key_mode == "pair" else (r["src_ip"],) if self.key_mode == "src" else (r["dst_ip"],)

    def assign(self, conn, ev, aggregator):
        """Return incident id for event (creating / merging incidents as needed)."""
        key = self._key(ev)
        lst = self.by_key.setdefault(key, [])
        hits = [i for i in lst if i.first - self.window <= ev.ts <= i.last + self.window]
        if not hits:
            cur = conn.execute(
                "INSERT INTO incidents(src_ip,dst_ip,first_ts,last_ts,event_count,group_count,engines,top_signature,"
                "categories,max_severity,risk_score,risk_label,updated_wall) VALUES(?,?,?,?,0,0,'','','',0,0,'low',?)",
                (ev.src_ip, ev.dst_ip, ev.ts, ev.ts, time.time()))
            inc = Incident({"id": cur.lastrowid, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip, "first_ts": ev.ts,
                            "last_ts": ev.ts, "event_count": 0, "group_count": 0, "engines": "",
                            "max_severity": 0, "risk_score": 0, "risk_label": "low"})
            lst.append(inc)
            self.by_id[inc.id] = inc
        else:
            inc = hits[0]
            for other in hits[1:]:                      # event bridges two incidents -> merge
                self._merge(conn, inc, other, aggregator)
                lst.remove(other)
        return inc

    def _merge(self, conn, keep, gone, aggregator):
        keep.first, keep.last = min(keep.first, gone.first), max(keep.last, gone.last)
        keep.count += gone.count
        keep.groups += gone.groups
        keep.engines |= gone.engines
        keep.sigs.update(gone.sigs)
        keep.cats.update(gone.cats)
        keep.dsts |= gone.dsts
        keep.max_sev = max(keep.max_sev, gone.max_sev)
        conn.execute("UPDATE events SET incident_id=? WHERE incident_id=?", (keep.id, gone.id))
        aggregator.reassign(conn, gone.id, keep.id)
        conn.execute("DELETE FROM incidents WHERE id=?", (gone.id,))
        self.by_id.pop(gone.id, None)
        self.dirty.discard(gone.id)
        self.dirty.add(keep.id)

    def add_event(self, inc, ev, new_group):
        inc.first, inc.last = min(inc.first, ev.ts), max(inc.last, ev.ts)
        inc.count += 1
        if new_group:
            inc.groups += 1
        inc.engines.add(ev.engine)
        inc.sigs[ev.signature] += 1
        inc.cats[ev.category] += 1
        inc.max_sev = max(inc.max_sev, ev.severity)
        inc.dsts.add(ev.dst_ip)
        if ev.dst_role:
            inc.dst_role = ev.dst_role
        self.dirty.add(inc.id)

    def flush(self, conn):
        now = time.time()
        for iid in self.dirty:
            inc = self.by_id.get(iid)
            if inc is None:
                continue
            inc.update_risk()
            dst = inc.dst if len(inc.dsts) == 1 else f"{len(inc.dsts)} hosts"
            conn.execute(
                "UPDATE incidents SET dst_ip=?, first_ts=?, last_ts=?, event_count=?, group_count=?, engines=?,"
                " top_signature=?, categories=?, max_severity=?, risk_score=?, risk_label=?, updated_wall=? WHERE id=?",
                (dst, inc.first, inc.last, inc.count, inc.groups, ",".join(sorted(inc.engines)),
                 inc.sigs.most_common(1)[0][0] if inc.sigs else "",
                 json.dumps([c for c, _ in inc.cats.most_common(5)]), inc.max_sev, inc.score, inc.label, now, iid))
        self.dirty.clear()
