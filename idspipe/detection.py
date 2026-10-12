"""Stage 4 - Detection engine.
Rule-based detection is done by Suricata and Snort themselves (their alerts are ingested as-is).
This module adds the OPTIONAL AI-based detector: an IsolationForest on flow features.
Its events are tagged engine='ml' and are never mixed into the Snort/Suricata alert counts."""
import os

from .models import UnifiedEvent
from .preprocess import flow_features


class MLDetector:
    def __init__(self, cfg):
        self.ok = False
        path = cfg["paths"]["ml_model"]
        if not os.path.exists(path):
            print(f"[ml] model not found at {path}. Run: python run_pipeline.py train-ml --eve <benign eve.json>. ML disabled.")
            return
        import joblib
        m = joblib.load(path)
        self.model, self.scaler, self.threshold = m["model"], m["scaler"], m["threshold"]
        self.ok = True

    def detect(self, flows, limit=200):
        if not self.ok or not flows:
            return []
        X = self.scaler.transform([flow_features(f) for f in flows])
        scores = self.model.decision_function(X)
        out = []
        for f, s in sorted(zip(flows, scores), key=lambda t: t[1]):
            if s >= self.threshold or len(out) >= limit:
                break
            out.append(UnifiedEvent(
                ts=f["ts"], engine="ml", sid=9000001, gid=9, rev=1,
                signature="ML anomaly: abnormal flow (IsolationForest)", category="Anomalous Flow",
                severity=2, src_ip=f["src_ip"], src_port=f["src_port"], dst_ip=f["dst_ip"],
                dst_port=f["dst_port"], proto=f["proto"], raw=f"score={s:.4f}"))
        return out


def train(eve_path, out_path, contamination=0.01):
    import joblib
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from .parsers import parse_suricata
    X = []
    with open(eve_path) as f:
        for line in f:
            if '"flow"' not in line:
                continue
            try:
                kind, fl = parse_suricata(line)
            except Exception:
                continue
            if kind == "flow":
                X.append(flow_features(fl))
    if len(X) < 100:
        raise SystemExit(f"Only {len(X)} flows found in {eve_path}; need a real benign capture (e.g. Monday).")
    sc = StandardScaler().fit(X)
    Z = sc.transform(X)
    m = IsolationForest(n_estimators=200, contamination=contamination, random_state=42, n_jobs=-1).fit(Z)
    thr = float(sorted(m.decision_function(Z))[int(len(Z) * contamination)])
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    joblib.dump({"model": m, "scaler": sc, "threshold": thr}, out_path)
    print(f"[ml] trained on {len(X)} flows -> {out_path} (threshold {thr:.4f})")
