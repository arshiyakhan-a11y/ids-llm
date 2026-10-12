"""Pipeline orchestrator: runs stages 1-7 and feeds stage 8 (LLM) + output."""
import threading
import time
from collections import defaultdict

from . import db
from .aggregation import Aggregator
from .assets import AssetInventory, load_assets
from .correlation import Correlator
from .detection import MLDetector
from .notifier import Notifier
from .parsers import PARSERS
from .preprocess import minute_bin
from .tailer import read_new_lines


class Source:
    def __init__(self, name, path, fmt):
        self.name, self.path, self.fmt, self.parse = name, path, fmt, PARSERS[fmt]


class Pipeline:
    def __init__(self, cfg, reset=False):
        self.cfg = cfg
        if reset:
            db.reset(cfg["paths"]["db"])
        self.conn = db.connect(cfg["paths"]["db"])
        p = cfg["pipeline"]
        self.batch = int(p.get("batch_lines", 5000))
        self.poll = float(p.get("poll_interval", 1.0))
        self.store_flows = bool(p.get("store_flows", False))
        self.assets = AssetInventory(cfg["paths"]["assets_file"])
        load_assets(self.assets, self.conn)
        self.agg = Aggregator(p.get("aggregation_window_sec", 60))
        self.cor = Correlator(p.get("correlation_window_sec", 300), p.get("correlation_key", "pair"))
        self.agg.load(self.conn)
        self.cor.load(self.conn)
        self.notifier = Notifier(cfg)
        self.ml = MLDetector(cfg) if cfg["ml"].get("enabled") else None
        snort_fmt = "snort_fast" if cfg["snort"].get("format", "json") == "fast" else "snort_json"
        self.sources = [Source("suricata", cfg["paths"]["suricata_eve"], "eve"),
                        Source("snort", cfg["paths"]["snort_alerts"], snort_fmt)]
        self.offsets = {r["path"]: r["offset"] for r in self.conn.execute("SELECT * FROM offsets")}
        self.stats = {s.name: {"lines_read": 0, "alerts": 0, "flows": 0, "parse_errors": 0, "skipped": 0} for s in self.sources}
        for r in self.conn.execute("SELECT * FROM ingest_stats"):
            if r["source"] in self.stats:
                self.stats[r["source"]] = {k: r[k] for k in self.stats[r["source"]]}
        self.fs = defaultdict(lambda: [0, 0, 0])
        self.ml_buf = []

    # ---------------------------------------------------------------- per record
    def handle_alert(self, ev):
        self.assets.touch(ev.src_ip, ev.ts)
        self.assets.touch(ev.dst_ip, ev.ts)
        ev.src_role, ev.dst_role = self.assets.role(ev.src_ip), self.assets.role(ev.dst_ip)
        inc = self.cor.assign(self.conn, ev, self.agg)          # stage 5
        before = len(self.agg.by_id)
        gid = self.agg.add(self.conn, ev, inc.id)               # stage 6
        self.cor.add_event(inc, ev, len(self.agg.by_id) > before)
        self.conn.execute(                                       # stage 7 (unified event)
            "INSERT INTO events(ts,engine,sid,gid,rev,signature,category,severity,src_ip,src_port,dst_ip,dst_port,"
            "proto,flow_id,iface,src_role,dst_role,group_id,incident_id,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev.ts, ev.engine, ev.sid, ev.gid, ev.rev, ev.signature, ev.category, ev.severity, ev.src_ip, ev.src_port,
             ev.dst_ip, ev.dst_port, ev.proto, ev.flow_id, ev.iface, ev.src_role, ev.dst_role, gid, inc.id, ev.raw))

    def handle_flow(self, f):
        self.assets.observe_flow(f)                              # stage 1
        b = self.fs[minute_bin(f["ts"])]                         # stage 3
        b[0] += 1
        b[1] += f["bytes_ts"] + f["bytes_tc"]
        b[2] += f["pkts_ts"] + f["pkts_tc"]
        if self.store_flows:
            self.conn.execute("INSERT INTO flows(ts,src_ip,src_port,dst_ip,dst_port,proto,duration,pkts,bytes,alerted) VALUES(?,?,?,?,?,?,?,?,?,?)",
                              (f["ts"], f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["proto"], f["age"],
                               f["pkts_ts"] + f["pkts_tc"], f["bytes_ts"] + f["bytes_tc"], f["alerted"]))
        if self.ml:
            self.ml_buf.append(f)

    # ---------------------------------------------------------------- one polling step
    def step(self):
        total = 0
        for s in self.sources:
            off = self.offsets.get(s.path, 0)
            lines, new_off = read_new_lines(s.path, off, self.batch)
            if not lines and new_off == off:
                continue
            st = self.stats[s.name]
            for line in lines:
                st["lines_read"] += 1
                line = line.strip()
                if not line:
                    st["skipped"] += 1
                    continue
                try:
                    kind, obj = s.parse(line, self.cfg)
                except Exception:
                    st["parse_errors"] += 1
                    continue
                if kind == "alert":
                    st["alerts"] += 1
                    self.handle_alert(obj)
                elif kind == "flow":
                    st["flows"] += 1
                    self.handle_flow(obj)
                elif kind == "meta":
                    self.assets.observe_meta(obj)
                    st["skipped"] += 1
                else:
                    st["skipped"] += 1
            if self.ml and self.ml_buf:                          # stage 4 (AI-based)
                for ev in self.ml.detect(self.ml_buf, int(self.cfg["ml"].get("max_events_per_batch", 200))):
                    self.handle_alert(ev)
                self.ml_buf = []
            self.offsets[s.path] = new_off
            self.flush(s.path, new_off)
            total += len(lines)
        return total

    def flush(self, path=None, off=None):
        c = self.conn
        self.assets.flush(c)
        self.agg.flush(c)
        self.cor.flush(c)
        for m, (n, by, pk) in self.fs.items():
            c.execute("INSERT INTO flow_stats(minute,flows,bytes,pkts) VALUES(?,?,?,?) ON CONFLICT(minute) DO UPDATE SET "
                      "flows=flows+excluded.flows, bytes=bytes+excluded.bytes, pkts=pkts+excluded.pkts", (m, n, by, pk))
        self.fs.clear()
        for name, st in self.stats.items():
            c.execute("INSERT OR REPLACE INTO ingest_stats VALUES(?,?,?,?,?,?)",
                      (name, st["lines_read"], st["alerts"], st["flows"], st["parse_errors"], st["skipped"]))
        if path is not None:
            c.execute("INSERT OR REPLACE INTO offsets VALUES(?,?)", (path, off))
        self.notifier.check(c)
        c.commit()

    # ---------------------------------------------------------------- run modes
    def run_once(self):
        while self.step():
            pass
        self.flush()

    def run_forever(self, stop=None):
        from .llm_engine import llm_worker
        stop = stop or threading.Event()
        t = threading.Thread(target=llm_worker, args=(self.cfg, stop), daemon=True)
        t.start()
        last = 0
        print("[pipeline] running. Watching:\n  " + "\n  ".join(f"{s.name}: {s.path}" for s in self.sources))
        try:
            while not stop.is_set():
                n = self.step()
                if time.time() - last > 15:
                    last = time.time()
                    ev = self.conn.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
                    inc = self.conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
                    print(f"[pipeline] events={ev} incidents={inc}", flush=True)
                if n == 0:
                    stop.wait(self.poll)
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            self.flush()
