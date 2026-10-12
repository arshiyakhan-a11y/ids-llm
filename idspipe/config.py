import os
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv(root):
    p = os.path.join(root, ".env")
    if not os.path.exists(p):
        return
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def load_config(path=None):
    path = os.path.abspath(path or os.path.join(ROOT, "config.yaml"))
    root = os.path.dirname(path)
    _load_dotenv(root)
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    for k, v in list(cfg.get("paths", {}).items()):
        if not os.path.isabs(v):
            cfg["paths"][k] = os.path.join(root, v)
    cfg["_root"] = root
    for sec in ("snort", "pipeline", "ml", "llm", "notifications"):
        cfg.setdefault(sec, {})
    return cfg
