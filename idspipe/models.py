from dataclasses import dataclass


@dataclass
class UnifiedEvent:
    """Stage 7: single normalised event format  (Asset + Threat + Severity + Time)."""
    ts: float
    engine: str            # suricata | snort | ml
    sid: int
    gid: int
    rev: int
    signature: str
    category: str
    severity: int          # 3 high, 2 medium, 1 low, 0 info
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    flow_id: int = 0
    iface: str = ""
    raw: str = ""
    src_role: str = ""
    dst_role: str = ""
    group_id: int = 0
    incident_id: int = 0
