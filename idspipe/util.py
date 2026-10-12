import datetime as dt
import ipaddress

SEV_LABEL = {3: "high", 2: "medium", 1: "low", 0: "info"}


def parse_iso(ts: str) -> float:
    """Parse Suricata timestamps like 2017-07-03T10:35:12.123456-0300"""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return dt.datetime.strptime(ts, fmt).timestamp()
        except ValueError:
            pass
    return dt.datetime.fromisoformat(ts).timestamp()


def fmt_ts(ts):
    if ts is None:
        return ""
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def prio_to_sev(p) -> int:
    """Suricata severity / Snort priority: 1=high 2=medium 3=low 4+=info -> 3..0"""
    try:
        p = int(p)
    except (TypeError, ValueError):
        return 1
    return {1: 3, 2: 2, 3: 1}.get(p, 0)


def to_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default
