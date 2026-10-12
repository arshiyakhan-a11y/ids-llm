"""Stage 3 - Pre-processing: 5-tuple flows -> features (duration, bytes, packets, rates)."""

import math

FEATURES = ["duration", "pkts_ts", "pkts_tc", "bytes_ts", "bytes_tc", "bytes_per_s", "pkts_per_s",
            "mean_pkt_size", "dst_port", "is_tcp", "is_udp", "syn", "rst"]


def flow_features(f):
    dur = max(f["age"], 0.0)
    pk = f["pkts_ts"] + f["pkts_tc"]
    by = f["bytes_ts"] + f["bytes_tc"]
    d = max(dur, 1e-3)
    heavy = [dur, f["pkts_ts"], f["pkts_tc"], f["bytes_ts"], f["bytes_tc"], by / d, pk / d, (by / pk) if pk else 0.0]
    # log1p tames the heavy tails of network counters (standard for flow-based anomaly detection)
    return [math.log1p(x) for x in heavy] + [f["dst_port"] / 65535.0, 1 if f["proto"] == "TCP" else 0,
                                              1 if f["proto"] == "UDP" else 0, f["syn"], f["rst"]]


def minute_bin(ts):
    return int(ts // 60) * 60
