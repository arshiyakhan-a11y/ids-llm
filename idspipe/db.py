import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, engine TEXT, sid INT, gid INT, rev INT,
  signature TEXT, category TEXT, severity INT, src_ip TEXT, src_port INT, dst_ip TEXT,
  dst_port INT, proto TEXT, flow_id INT, iface TEXT, src_role TEXT, dst_role TEXT,
  group_id INT, incident_id INT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_ev_inc ON events(incident_id);
CREATE INDEX IF NOT EXISTS ix_ev_eng ON events(engine);

CREATE TABLE IF NOT EXISTS groups(
  id INTEGER PRIMARY KEY AUTOINCREMENT, engine TEXT, sid INT, signature TEXT, category TEXT,
  severity INT, src_ip TEXT, dst_ip TEXT, last_dst_port INT, first_ts REAL, last_ts REAL,
  count INT, incident_id INT);
CREATE INDEX IF NOT EXISTS ix_gr_inc ON groups(incident_id);

CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, src_ip TEXT, dst_ip TEXT, first_ts REAL, last_ts REAL,
  event_count INT, group_count INT, engines TEXT, top_signature TEXT, categories TEXT,
  max_severity INT, risk_score REAL, risk_label TEXT, updated_wall REAL, notified INT DEFAULT 0,
  llm_status TEXT DEFAULT 'pending', llm_attempts INT DEFAULT 0, llm_event_count INT DEFAULT 0,
  llm_json TEXT, llm_risk TEXT, llm_priority INT, llm_ts REAL, llm_error TEXT);
CREATE INDEX IF NOT EXISTS ix_inc_risk ON incidents(risk_score);

CREATE TABLE IF NOT EXISTS assets(
  ip TEXT PRIMARY KEY, role TEXT, device_type TEXT, internal INT, hostname TEXT, ports TEXT,
  first_seen REAL, last_seen REAL, known INT, flows INT);

CREATE TABLE IF NOT EXISTS offsets(path TEXT PRIMARY KEY, offset INT);
CREATE TABLE IF NOT EXISTS ingest_stats(
  source TEXT PRIMARY KEY, lines_read INT, alerts INT, flows INT, parse_errors INT, skipped INT);
CREATE TABLE IF NOT EXISTS flow_stats(minute INT PRIMARY KEY, flows INT, bytes INT, pkts INT);
CREATE TABLE IF NOT EXISTS flows(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, src_ip TEXT, src_port INT, dst_ip TEXT,
  dst_port INT, proto TEXT, duration REAL, pkts INT, bytes INT, alerted INT);
CREATE TABLE IF NOT EXISTS notifications(
  id INTEGER PRIMARY KEY AUTOINCREMENT, wall REAL, incident_id INT, level TEXT, message TEXT);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, wall REAL, path TEXT);
"""


def connect(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    return conn


def reset(path):
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass
