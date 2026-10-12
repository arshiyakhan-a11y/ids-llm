"""Stage 1 - Asset identification (passive, from observed traffic + optional assets.yaml)."""
import ipaddress
import json
import os
from collections import Counter

import yaml

from .util import is_private

PORT_HINTS = {
    80: ("Web server", "server"), 443: ("Web server (TLS)", "server"), 8080: ("Web server", "server"),
    22: ("SSH server", "server"), 21: ("FTP server", "server"), 23: ("Telnet device", "device"),
    25: ("Mail server", "server"), 53: ("DNS server", "server"), 123: ("NTP server", "server"),
    389: ("LDAP/Directory server", "server"), 445: ("SMB/Windows host", "server"),
    3389: ("RDP host", "workstation"), 3306: ("MySQL server", "server"), 5432: ("PostgreSQL server", "server"),
    554: ("IP camera (RTSP)", "iot"), 8554: ("IP camera (RTSP)", "iot"), 1883: ("IoT sensor (MQTT)", "iot"),
    8883: ("IoT sensor (MQTT/TLS)", "iot"), 5683: ("IoT device (CoAP)", "iot"),
    9100: ("Network printer", "device"), 502: ("Industrial device (Modbus)", "industrial"),
    102: ("Industrial device (S7)", "industrial"), 44818: ("Industrial device (EtherNet/IP)", "industrial"),
    20000: ("Industrial device (DNP3)", "industrial"), 47808: ("Building automation (BACnet)", "industrial"),
}


class AssetInventory:
    def __init__(self, assets_file=None):
        self.nets, self.known = [], {}
        if assets_file and os.path.exists(assets_file):
            with open(assets_file) as f:
                y = yaml.safe_load(f) or {}
            self.nets = [ipaddress.ip_network(n) for n in y.get("internal_nets", [])]
            self.known = {str(k): v for k, v in (y.get("assets") or {}).items()}
        self.assets = {}
        self.dirty = set()

    def internal(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.nets:
            return any(a in n for n in self.nets)
        return is_private(ip)

    def _get(self, ip, ts):
        a = self.assets.get(ip)
        if a is None:
            k = self.known.get(ip)
            a = {"ip": ip, "role": k["role"] if k else "", "device_type": k["device_type"] if k else "",
                 "internal": 1 if self.internal(ip) else 0, "hostname": "", "ports": Counter(),
                 "first_seen": ts, "last_seen": ts, "known": 1 if k else 0, "flows": 0}
            self.assets[ip] = a
        else:
            a["first_seen"] = min(a["first_seen"], ts)
            a["last_seen"] = max(a["last_seen"], ts)
        self.dirty.add(ip)
        return a

    def touch(self, ip, ts):
        if ip:
            self._get(ip, ts)

    def observe_flow(self, f):
        s, d = self._get(f["src_ip"], f["ts"]), self._get(f["dst_ip"], f["ts"])
        s["flows"] += 1
        d["flows"] += 1
        if f["proto"] in ("TCP", "UDP") and f["bytes_tc"] > 0 and f["dst_port"] <= 49151:
            d["ports"][f["dst_port"]] += 1      # the destination answered => it is a server on that port

    def observe_meta(self, m):
        if m.get("ip") and m.get("hostname"):
            self._get(m["ip"], 0)["hostname"] = m["hostname"]

    def _classify(self, a):
        if a["known"]:
            return
        ports = [p for p, _ in a["ports"].most_common(12)]
        for p in ports:
            if p in PORT_HINTS and (a["role"] == "" or PORT_HINTS[p][1] in ("iot", "industrial")):
                a["role"], a["device_type"] = PORT_HINTS[p]
                break
        if not a["role"]:
            if a["internal"]:
                a["role"], a["device_type"] = "Internal host", "host"
            else:
                a["role"], a["device_type"] = "External host", "external"

    def role(self, ip):
        a = self.assets.get(ip)
        if a is None:
            return ""
        self._classify(a)
        return a["role"]

    def flush(self, conn):
        for ip in list(self.dirty):
            a = self.assets[ip]
            self._classify(a)
            conn.execute(
                "INSERT OR REPLACE INTO assets(ip,role,device_type,internal,hostname,ports,first_seen,last_seen,known,flows)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (ip, a["role"], a["device_type"], a["internal"], a["hostname"],
                 json.dumps([p for p, _ in a["ports"].most_common(12)]),
                 a["first_seen"], a["last_seen"], a["known"], a["flows"]))
        self.dirty.clear()


def load_assets(inv, conn):
    """Restore inventory after a restart."""
    import json as _j
    for r in conn.execute("SELECT * FROM assets"):
        inv.assets[r["ip"]] = {
            "ip": r["ip"], "role": r["role"] or "", "device_type": r["device_type"] or "", "internal": r["internal"],
            "hostname": r["hostname"] or "", "ports": Counter({p: 1 for p in _j.loads(r["ports"] or "[]")}),
            "first_seen": r["first_seen"], "last_seen": r["last_seen"], "known": r["known"], "flows": r["flows"] or 0}
