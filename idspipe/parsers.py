"""Stage 2/3 helpers: turn raw Suricata / Snort log lines into normalised records.

Every parser returns (kind, obj):
  ("alert", UnifiedEvent) | ("flow", dict) | ("meta", dict) | ("skip", None)
Alerts are ONLY ever created from lines that Snort/Suricata wrote.
"""
import json
import re
import time
import datetime as dt

from .models import UnifiedEvent
from .util import parse_iso, prio_to_sev, to_int


# ------------------------------------------------------------------ Suricata
def parse_suricata(line, cfg=None):
    d = json.loads(line)
    et = d.get("event_type")
    if et == "alert":
        a = d.get("alert", {})
        return "alert", UnifiedEvent(
            ts=parse_iso(d["timestamp"]), engine="suricata",
            sid=to_int(a.get("signature_id")), gid=to_int(a.get("gid"), 1), rev=to_int(a.get("rev")),
            signature=a.get("signature", ""), category=a.get("category", ""),
            severity=prio_to_sev(a.get("severity")),
            src_ip=d.get("src_ip", ""), src_port=to_int(d.get("src_port")),
            dst_ip=d.get("dest_ip", ""), dst_port=to_int(d.get("dest_port")),
            proto=str(d.get("proto", "")).upper(), flow_id=to_int(d.get("flow_id")),
            iface=d.get("in_iface", ""), raw=line)
    if et == "flow":
        f = d.get("flow", {})
        tcp = d.get("tcp", {}) or {}
        return "flow", {
            "ts": parse_iso(d["timestamp"]),
            "src_ip": d.get("src_ip", ""), "src_port": to_int(d.get("src_port")),
            "dst_ip": d.get("dest_ip", ""), "dst_port": to_int(d.get("dest_port")),
            "proto": str(d.get("proto", "")).upper(),
            "pkts_ts": to_int(f.get("pkts_toserver")), "pkts_tc": to_int(f.get("pkts_toclient")),
            "bytes_ts": to_int(f.get("bytes_toserver")), "bytes_tc": to_int(f.get("bytes_toclient")),
            "age": float(f.get("age", 0) or 0), "alerted": 1 if f.get("alerted") else 0,
            "syn": 1 if tcp.get("syn") else 0, "rst": 1 if tcp.get("rst") else 0,
            "app_proto": d.get("app_proto", "")}
    if et == "http":
        h = d.get("http", {})
        return "meta", {"ip": d.get("dest_ip", ""), "hostname": h.get("hostname", ""),
                        "src_ip": d.get("src_ip", ""), "ua": h.get("http_user_agent", "")}
    return "skip", None


# ---------------------------------------------------------------- Snort JSON
def _snort_ts_from_text(ts, year):
    # "09/09-11:24:28.102081" (local time, no year)
    m = re.match(r"(\d{2})/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", ts or "")
    if not m:
        return time.time()
    mo, dd, hh, mi, ss, us = m.groups()
    t = dt.datetime(year, int(mo), int(dd), int(hh), int(mi), int(ss), int((us or "0").ljust(6, "0")[:6]))
    return time.mktime(t.timetuple()) + t.microsecond / 1e6


def parse_snort_json(line, cfg=None):
    d = json.loads(line)
    if "msg" not in d and "rule" not in d:
        return "skip", None
    year = int((cfg or {}).get("snort", {}).get("fast_year", 2017))
    gid, sid, rev = to_int(d.get("gid"), 1), to_int(d.get("sid")), to_int(d.get("rev"))
    rule = str(d.get("rule", ""))
    if rule.count(":") == 2 and not d.get("sid"):
        gid, sid, rev = [to_int(x) for x in rule.split(":")]
    if d.get("seconds") not in (None, ""):
        ts = float(d["seconds"])
    else:
        ts = _snort_ts_from_text(d.get("timestamp", ""), year)
    src, sp = d.get("src_addr", ""), to_int(d.get("src_port"))
    dst, dp = d.get("dst_addr", ""), to_int(d.get("dst_port"))
    if not src and d.get("src_ap"):
        src, _, p = str(d["src_ap"]).rpartition(":"); sp = to_int(p)
    if not dst and d.get("dst_ap"):
        dst, _, p = str(d["dst_ap"]).rpartition(":"); dp = to_int(p)
    return "alert", UnifiedEvent(
        ts=ts, engine="snort", sid=sid, gid=gid, rev=rev,
        signature=d.get("msg", ""), category=d.get("class", ""),
        severity=prio_to_sev(d.get("priority")),
        src_ip=src, src_port=sp, dst_ip=dst, dst_port=dp,
        proto=str(d.get("proto", "")).upper(), iface=d.get("iface", ""), raw=line)


# ---------------------------------------------------------------- Snort fast
_FAST = re.compile(
    r"^(?:(\d{2,4})/)?(\d{2})/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+(?:\[\*\*\]\s+)?"
    r"\[(\d+):(\d+):(\d+)\]\s+\"?(.*?)\"?\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s*(.*?)\]\s+)?(?:\[Priority:\s*(\d+)\]\s+)?"
    r"\{(\w+)\}\s+([0-9A-Fa-f\.:]+?)(?::(\d+))?\s+->\s+([0-9A-Fa-f\.:]+?)(?::(\d+))?\s*$")


def parse_snort_fast(line, cfg=None):
    m = _FAST.match(line.strip())
    if not m:
        raise ValueError("unrecognised snort fast line")
    yr, mo, dd, hh, mi, ss, us, gid, sid, rev, msg, cls, pri, proto, src, sp, dst, dp = m.groups()
    year = int(yr) + (2000 if yr and len(yr) == 2 else 0) if yr else int((cfg or {}).get("snort", {}).get("fast_year", 2017))
    t = dt.datetime(year, int(mo), int(dd), int(hh), int(mi), int(ss), int((us or "0").ljust(6, "0")[:6]))
    ts = time.mktime(t.timetuple()) + t.microsecond / 1e6
    return "alert", UnifiedEvent(
        ts=ts, engine="snort", sid=int(sid), gid=int(gid), rev=int(rev), signature=msg, category=cls or "",
        severity=prio_to_sev(pri), src_ip=src, src_port=to_int(sp), dst_ip=dst, dst_port=to_int(dp),
        proto=proto.upper(), raw=line)


PARSERS = {"eve": parse_suricata, "snort_json": parse_snort_json, "snort_fast": parse_snort_fast}


def count_raw_alerts(path, fmt):
    """Independent count of alert lines in a raw file (used by the audit)."""
    n = 0
    try:
        with open(path, "rb") as f:
            for b in f:
                if not b.endswith(b"\n"):
                    continue
                if fmt == "eve":
                    if b'"event_type":"alert"' in b or b'"event_type": "alert"' in b:
                        n += 1
                elif fmt == "snort_json":
                    s = b.strip()
                    if s.startswith(b"{") and (b'"msg"' in s or b'"rule"' in s):
                        n += 1
                else:
                    if b"[**]" in b:
                        n += 1
    except FileNotFoundError:
        pass
    return n
